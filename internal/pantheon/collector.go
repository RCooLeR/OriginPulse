package pantheon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"originpulse/internal/config"
	"originpulse/internal/jobs"
)

type Collector struct {
	cfg            config.Config
	jobs           *jobs.Store
	rawFiles       *RawFileRepository
	downloader     logDownloader
	cooldownMu     sync.Mutex
	serverCooldown map[string]time.Time
}

type logDownloader interface {
	DownloadLogs(ctx context.Context, jobID string, target Target, serverKind string, serverAddress string, containerID string, repo *RawFileRepository) (DownloadStats, error)
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
		cfg:            cfg,
		jobs:           store,
		rawFiles:       rawFiles,
		downloader:     NewSFTPDownloader(cfg, store),
		serverCooldown: make(map[string]time.Time),
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

	meta := map[string]any{
		"site_id": site.ID,
		"env":     env,
	}
	job := c.jobs.Start(ctx, "collect_site_env", triggeredBy, meta)
	if site.SourceType == "local" {
		return c.collectLocalSiteEnv(ctx, job.ID, site, env)
	}

	target := BuildTarget(site, env)
	resolver := net.Resolver{}

	appStep := c.jobs.StartStep(ctx, job.ID, "discover appservers", map[string]any{"site_id": site.ID, "env": env, "host": target.AppserverDNS})
	appIPs, appErr := c.lookup(ctx, &resolver, target.AppserverDNS)
	c.jobs.FinishStep(appStep, stepStatus(appErr), dnsStepMessage(appIPs, appErr), appErr, map[string]any{"addresses": appIPs, "address_count": len(appIPs)})
	dbStep := c.jobs.StartStep(ctx, job.ID, "discover dbservers", map[string]any{"site_id": site.ID, "env": env, "host": target.DBServerDNS})
	dbIPs, dbErr := c.lookup(ctx, &resolver, target.DBServerDNS)
	c.jobs.FinishStep(dbStep, stepStatus(dbErr), dnsStepMessage(dbIPs, dbErr), dbErr, map[string]any{"addresses": dbIPs, "address_count": len(dbIPs)})
	target.AppserverIPs = appIPs
	target.DBServerIPs = dbIPs

	dirStep := c.jobs.StartStep(ctx, job.ID, "prepare raw directory", map[string]any{"site_id": site.ID, "env": env})
	siteDir := filepath.Join(c.cfg.RawDir(), site.ID, env)
	if err := os.MkdirAll(siteDir, 0o750); err != nil {
		c.jobs.FinishStep(dirStep, jobs.StatusFailed, "failed to create raw directory", err, map[string]any{"path": siteDir})
		c.jobs.Finish(job.ID, jobs.StatusFailed, "failed to create raw archive directory", err)
		return err
	}
	c.jobs.FinishStep(dirStep, jobs.StatusSuccess, "raw directory ready", nil, map[string]any{"path": siteDir})

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
	planStep := c.jobs.StartStep(ctx, job.ID, "write collection plan", map[string]any{"site_id": site.ID, "env": env, "path": manifestPath})
	if err := os.WriteFile(manifestPath, []byte(target.Manifest(c.cfg.Pantheon.SFTPPort)), 0o640); err != nil {
		c.jobs.FinishStep(planStep, jobs.StatusFailed, "failed to write collection plan", err, nil)
		c.jobs.Finish(job.ID, jobs.StatusFailed, "failed to write collection plan", err)
		return err
	}
	c.jobs.FinishStep(planStep, jobs.StatusSuccess, "collection plan written", nil, nil)

	stats, err := c.downloadTargetLogs(ctx, job.ID, target)
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
		Int("server_failures", stats.ServersFailed).
		Int("servers_skipped", stats.ServersSkipped).
		Int("servers_locked", stats.ServersLocked).
		Int64("bytes_downloaded", stats.BytesDownloaded).
		Msg("collection completed")

	message := fmt.Sprintf("downloaded %d files, skipped %d", stats.FilesDownloaded, stats.FilesSkipped)
	if stats.ServersFailed > 0 {
		message = fmt.Sprintf("%s, server failures %d", message, stats.ServersFailed)
	}
	if stats.ServersSkipped > 0 {
		message = fmt.Sprintf("%s, servers on cooldown %d", message, stats.ServersSkipped)
	}
	if stats.ServersLocked > 0 {
		message = fmt.Sprintf("%s, servers locked %d", message, stats.ServersLocked)
	}
	c.jobs.FinishWithMeta(job.ID, jobs.StatusSuccess, message, nil, map[string]any{
		"files_seen":        stats.FilesSeen,
		"files_downloaded":  stats.FilesDownloaded,
		"files_skipped":     stats.FilesSkipped,
		"bytes_downloaded":  stats.BytesDownloaded,
		"servers_attempted": stats.ServersAttempted,
		"servers_succeeded": stats.ServersSucceeded,
		"server_failures":   stats.ServersFailed,
		"servers_skipped":   stats.ServersSkipped,
		"servers_locked":    stats.ServersLocked,
	})
	return nil
}

func (c *Collector) downloadTargetLogs(ctx context.Context, jobID string, target Target) (DownloadStats, error) {
	type serverTarget struct {
		kind        string
		ip          string
		containerID string
	}
	type serverResult struct {
		target  serverTarget
		stats   DownloadStats
		err     error
		skipped bool
	}

	servers := make([]serverTarget, 0, len(target.AppserverIPs)+len(target.DBServerIPs))
	for _, ip := range target.AppserverIPs {
		servers = append(servers, serverTarget{kind: "appserver", ip: ip, containerID: ContainerID("appserver", ip)})
	}
	for _, ip := range target.DBServerIPs {
		servers = append(servers, serverTarget{kind: "dbserver", ip: ip, containerID: ContainerID("dbserver", ip)})
	}

	results := make(chan serverResult, len(servers))
	var wg sync.WaitGroup
	for _, server := range servers {
		server := server
		wg.Add(1)
		go func() {
			defer wg.Done()
			if until, ok := c.cooldownUntil(ctx, target, server.kind, server.ip); ok {
				meta := map[string]any{
					"site_id":                    target.SiteID,
					"env":                        target.Environment,
					"server_kind":                server.kind,
					"server":                     server.ip,
					"container_id":               server.containerID,
					"cooldown_until":             until.UTC().Format(time.RFC3339),
					"cooldown_seconds_remaining": int(time.Until(until).Round(time.Second).Seconds()),
				}
				step := c.jobs.StartStep(ctx, jobID, "skip locked server", meta)
				c.jobs.FinishStep(step, jobs.StatusSkipped, "Pantheon resource lock cooldown active", nil, meta)
				results <- serverResult{target: server, skipped: true}
				return
			}
			stats, err := c.downloader.DownloadLogs(ctx, jobID, target, server.kind, server.ip, server.containerID, c.rawFiles)
			if isPantheonResourceLocked(err) {
				until := c.markCooldown(ctx, target, server.kind, server.ip, err)
				step := c.jobs.StartStep(ctx, jobID, "cooldown locked server", map[string]any{
					"site_id":        target.SiteID,
					"env":            target.Environment,
					"server_kind":    server.kind,
					"server":         server.ip,
					"container_id":   server.containerID,
					"cooldown_until": until.UTC().Format(time.RFC3339),
				})
				c.jobs.FinishStep(step, jobs.StatusSkipped, "Pantheon resource lock cooldown started", err, map[string]any{
					"cooldown_until":   until.UTC().Format(time.RFC3339),
					"cooldown_seconds": int(c.lockCooldown().Seconds()),
				})
			}
			results <- serverResult{target: server, stats: stats, err: err}
		}()
	}
	wg.Wait()
	close(results)

	var total DownloadStats
	var firstErr error
	for result := range results {
		if result.skipped {
			total.ServersSkipped++
			continue
		}
		total.ServersAttempted++
		total.add(result.stats)
		if result.err == nil {
			total.ServersSucceeded++
			continue
		}

		locked := isPantheonResourceLocked(result.err)
		if locked {
			total.ServersLocked++
		} else {
			total.ServersFailed++
			total.ServerErrors = append(total.ServerErrors, fmt.Sprintf("%s %s: %v", result.target.kind, result.target.ip, result.err))
			if firstErr == nil {
				firstErr = fmt.Errorf("%s %s: %w", result.target.kind, result.target.ip, result.err)
			}
		}
		event := log.Error().Err(result.err).Str("site_id", target.SiteID).Str("env", target.Environment).Str("server", result.target.ip)
		if locked {
			event = log.Warn().Err(result.err).Str("site_id", target.SiteID).Str("env", target.Environment).Str("server", result.target.ip)
		}
		if result.target.kind == "appserver" {
			if locked {
				event.Msg("appserver log download locked; cooldown started")
			} else {
				event.Msg("appserver log download failed")
			}
		} else {
			if locked {
				event.Msg("dbserver log download locked; cooldown started")
			} else {
				event.Msg("dbserver log download failed")
			}
		}
	}

	if total.ServersAttempted > 0 && total.ServersSucceeded == 0 && firstErr != nil {
		return total, firstErr
	}
	return total, nil
}

func (c *Collector) cooldownUntil(ctx context.Context, target Target, serverKind string, serverIP string) (time.Time, bool) {
	key := cooldownKey(target, serverKind, serverIP)
	now := time.Now()
	c.cooldownMu.Lock()
	until, ok := c.serverCooldown[key]
	if ok && !now.Before(until) {
		delete(c.serverCooldown, key)
		ok = false
	}
	c.cooldownMu.Unlock()

	if ok {
		return until, true
	}
	if c.rawFiles == nil {
		return time.Time{}, false
	}

	until, ok, err := c.rawFiles.ServerCooldownUntil(ctx, target.SiteID, target.Environment, serverKind, serverIP)
	if err != nil {
		log.Warn().
			Err(err).
			Str("site_id", target.SiteID).
			Str("env", target.Environment).
			Str("server_kind", serverKind).
			Str("server", serverIP).
			Msg("failed to read persisted Pantheon server cooldown")
		return time.Time{}, false
	}
	if ok {
		c.cooldownMu.Lock()
		c.serverCooldown[key] = until
		c.cooldownMu.Unlock()
	}
	return until, ok
}

func (c *Collector) markCooldown(ctx context.Context, target Target, serverKind string, serverIP string, reason error) time.Time {
	key := cooldownKey(target, serverKind, serverIP)
	until := time.Now().Add(c.lockCooldown())
	c.cooldownMu.Lock()
	c.serverCooldown[key] = until
	c.cooldownMu.Unlock()
	if c.rawFiles != nil {
		reasonText := ""
		if reason != nil {
			reasonText = reason.Error()
		}
		if err := c.rawFiles.MarkServerCooldown(ctx, target.SiteID, target.Environment, serverKind, serverIP, until, reasonText); err != nil {
			log.Warn().
				Err(err).
				Str("site_id", target.SiteID).
				Str("env", target.Environment).
				Str("server_kind", serverKind).
				Str("server", serverIP).
				Msg("failed to persist Pantheon server cooldown")
		}
	}
	return until
}

func (c *Collector) lockCooldown() time.Duration {
	if c.cfg.Collection.ServerLockCooldown > 0 {
		return c.cfg.Collection.ServerLockCooldown
	}
	return 15 * time.Minute
}

func cooldownKey(target Target, serverKind string, serverIP string) string {
	return target.SiteID + "|" + target.Environment + "|" + serverKind + "|" + serverIP
}

func isPantheonResourceLocked(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "requested resource is locked") ||
		(strings.Contains(message, "administratively prohibited") && strings.Contains(message, "pantheon"))
}

func stepStatus(err error) jobs.Status {
	if err != nil {
		return jobs.StatusFailed
	}
	return jobs.StatusSuccess
}

func dnsStepMessage(addresses []string, err error) string {
	if err != nil {
		return "DNS discovery failed"
	}
	return fmt.Sprintf("resolved %d address(es)", len(addresses))
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
