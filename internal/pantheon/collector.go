package pantheon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"originpulse/internal/config"
	"originpulse/internal/jobs"
)

type Collector struct {
	cfg        config.Config
	jobs       *jobs.Store
	rawFiles   *RawFileRepository
	downloader *SFTPDownloader
}

type Target struct {
	SiteID         string   `json:"site_id"`
	SiteName       string   `json:"site_name"`
	Environment    string   `json:"environment"`
	PantheonSiteID string   `json:"pantheon_site_id"`
	SFTPUser       string   `json:"sftp_user"`
	AppserverDNS   string   `json:"appserver_dns"`
	DBServerDNS    string   `json:"dbserver_dns"`
	AppserverIPs   []string `json:"appserver_ips,omitempty"`
	DBServerIPs    []string `json:"dbserver_ips,omitempty"`
}

func NewCollector(cfg config.Config, store *jobs.Store, rawFiles *RawFileRepository) *Collector {
	return &Collector{
		cfg:        cfg,
		jobs:       store,
		rawFiles:   rawFiles,
		downloader: NewSFTPDownloader(cfg),
	}
}

func (c *Collector) CollectAll(ctx context.Context) error {
	if c.rawFiles != nil {
		return c.rawFiles.WithCollectionLock(ctx, c.collectAll)
	}
	return c.collectAll(ctx)
}

func (c *Collector) collectAll(ctx context.Context) error {
	if !c.cfg.Collection.Enabled {
		job := c.jobs.Start(ctx, "collect_all", "scheduler", nil)
		c.jobs.Finish(job.ID, jobs.StatusSkipped, "collection is disabled in config", nil)
		return nil
	}

	if err := os.MkdirAll(c.cfg.RawDir(), 0o750); err != nil {
		return err
	}

	sites := c.cfg.EnabledSites()
	if len(sites) == 0 {
		job := c.jobs.Start(ctx, "collect_all", "scheduler", nil)
		c.jobs.Finish(job.ID, jobs.StatusSkipped, "no enabled sites configured", nil)
		return nil
	}

	workerCount := c.cfg.Collection.MaxParallelSites
	sem := make(chan struct{}, workerCount)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex

	for _, site := range sites {
		for _, env := range site.Envs {
			site := site
			env := env
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				if err := c.CollectSiteEnv(ctx, site, env, "scheduler"); err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
				}
			}()
		}
	}

	wg.Wait()
	return firstErr
}

func (c *Collector) CollectSiteEnv(ctx context.Context, site config.SiteConfig, env string, triggeredBy string) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Collection.TimeoutPerSite)
	defer cancel()

	meta := map[string]string{
		"site_id": site.ID,
		"env":     env,
	}
	job := c.jobs.Start(ctx, "collect_site_env", triggeredBy, meta)

	target := BuildTarget(site, env)
	resolver := net.Resolver{}

	appIPs, appErr := c.lookup(ctx, &resolver, target.AppserverDNS)
	dbIPs, dbErr := c.lookup(ctx, &resolver, target.DBServerDNS)
	target.AppserverIPs = appIPs
	target.DBServerIPs = dbIPs

	siteDir := filepath.Join(c.cfg.RawDir(), site.ID, env)
	if err := os.MkdirAll(siteDir, 0o750); err != nil {
		c.jobs.Finish(job.ID, jobs.StatusFailed, "failed to create raw archive directory", err)
		return err
	}

	if appErr != nil || dbErr != nil {
		if len(appIPs) == 0 && len(dbIPs) == 0 {
			err := fmt.Errorf("dns discovery failed: appserver=%v dbserver=%v", appErr, dbErr)
			c.jobs.Finish(job.ID, jobs.StatusFailed, "Pantheon DNS discovery failed", err)
			return err
		}
		log.Warn().
			Str("job_id", job.ID).
			Str("site_id", site.ID).
			Str("env", env).
			Err(fmt.Errorf("appserver=%v dbserver=%v", appErr, dbErr)).
			Msg("Pantheon DNS discovery partially failed")
	}

	manifestPath := filepath.Join(siteDir, "collection-plan.txt")
	if err := os.WriteFile(manifestPath, []byte(target.Manifest(c.cfg.Pantheon.SFTPPort)), 0o640); err != nil {
		c.jobs.Finish(job.ID, jobs.StatusFailed, "failed to write collection plan", err)
		return err
	}

	stats, err := c.downloadTargetLogs(ctx, target)
	if err != nil {
		c.jobs.Finish(job.ID, jobs.StatusFailed, "SFTP log collection failed", err)
		return err
	}

	log.Info().
		Str("job_id", job.ID).
		Str("site_id", site.ID).
		Str("env", env).
		Int("appservers", len(appIPs)).
		Int("dbservers", len(dbIPs)).
		Int("files_seen", stats.FilesSeen).
		Int("files_downloaded", stats.FilesDownloaded).
		Int("files_skipped", stats.FilesSkipped).
		Int64("bytes_downloaded", stats.BytesDownloaded).
		Msg("collection completed")

	c.jobs.Finish(job.ID, jobs.StatusSuccess, fmt.Sprintf("downloaded %d files, skipped %d", stats.FilesDownloaded, stats.FilesSkipped), nil)
	return nil
}

func (c *Collector) downloadTargetLogs(ctx context.Context, target Target) (DownloadStats, error) {
	var total DownloadStats
	var firstErr error
	attempted := 0
	succeeded := 0

	for _, ip := range target.AppserverIPs {
		attempted++
		containerID := ContainerID("appserver", ip)
		stats, err := c.downloader.DownloadLogs(ctx, target, "appserver", ip, containerID, c.rawFiles)
		total.add(stats)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("appserver %s: %w", ip, err)
			}
			log.Error().Err(err).Str("site_id", target.SiteID).Str("env", target.Environment).Str("server", ip).Msg("appserver log download failed")
			continue
		}
		succeeded++
	}

	for _, ip := range target.DBServerIPs {
		attempted++
		containerID := ContainerID("dbserver", ip)
		stats, err := c.downloader.DownloadLogs(ctx, target, "dbserver", ip, containerID, c.rawFiles)
		total.add(stats)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("dbserver %s: %w", ip, err)
			}
			log.Error().Err(err).Str("site_id", target.SiteID).Str("env", target.Environment).Str("server", ip).Msg("dbserver log download failed")
			continue
		}
		succeeded++
	}

	if attempted > 0 && succeeded == 0 && firstErr != nil {
		return total, firstErr
	}
	return total, nil
}

func (c *Collector) Plan(ctx context.Context) ([]Target, error) {
	targets := make([]Target, 0)
	resolver := net.Resolver{}

	for _, site := range c.cfg.EnabledSites() {
		for _, env := range site.Envs {
			target := BuildTarget(site, env)
			lookupCtx, cancel := context.WithTimeout(ctx, c.cfg.Pantheon.DNSTimeout)
			target.AppserverIPs, _ = c.lookup(lookupCtx, &resolver, target.AppserverDNS)
			target.DBServerIPs, _ = c.lookup(lookupCtx, &resolver, target.DBServerDNS)
			cancel()
			targets = append(targets, target)
		}
	}

	return targets, nil
}

func (c *Collector) CredentialSummary() config.CredentialSummary {
	return c.cfg.CredentialSummary()
}

func (c *Collector) lookup(ctx context.Context, resolver *net.Resolver, host string) ([]string, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, c.cfg.Pantheon.DNSTimeout)
	defer cancel()
	return resolver.LookupHost(lookupCtx, host)
}

func BuildTarget(site config.SiteConfig, env string) Target {
	appserverDNS := fmt.Sprintf("appserver.%s.%s.drush.in", env, site.PantheonSiteID)
	dbserverDNS := fmt.Sprintf("dbserver.%s.%s.drush.in", env, site.PantheonSiteID)
	return Target{
		SiteID:         site.ID,
		SiteName:       site.Name,
		Environment:    env,
		PantheonSiteID: site.PantheonSiteID,
		SFTPUser:       fmt.Sprintf("%s.%s", env, site.PantheonSiteID),
		AppserverDNS:   appserverDNS,
		DBServerDNS:    dbserverDNS,
	}
}

func (t Target) Manifest(port int) string {
	return "site_id=" + t.SiteID + "\n" +
		"site_name=" + t.SiteName + "\n" +
		"environment=" + t.Environment + "\n" +
		"pantheon_site_id=" + t.PantheonSiteID + "\n" +
		"sftp_user=" + t.SFTPUser + "\n" +
		"sftp_port=" + strconv.Itoa(port) + "\n" +
		"appserver_dns=" + t.AppserverDNS + "\n" +
		"appserver_ips=" + join(t.AppserverIPs) + "\n" +
		"dbserver_dns=" + t.DBServerDNS + "\n" +
		"dbserver_ips=" + join(t.DBServerIPs) + "\n" +
		"generated_at=" + time.Now().UTC().Format(time.RFC3339) + "\n"
}

func join(values []string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, value := range values[1:] {
		out += "," + value
	}
	return out
}
