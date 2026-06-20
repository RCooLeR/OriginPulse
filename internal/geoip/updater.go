package geoip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type UpdaterConfig struct {
	DBPath           string
	SeedPath         string
	DownloadURL      string
	AccountID        string
	LicenseKey       string
	Interval         time.Duration
	LastModifiedPath string
	HTTPTimeout      time.Duration
}

type Updater struct {
	cfg UpdaterConfig
}

func NewUpdater(cfg UpdaterConfig) *Updater {
	return &Updater{cfg: cfg}
}

func (u *Updater) EnsureAndLoad(ctx context.Context, mgr *Manager) error {
	if err := u.ensureDatabase(ctx); err != nil {
		return err
	}
	return mgr.Load()
}

func (u *Updater) ensureDatabase(ctx context.Context) error {
	if _, err := os.Stat(u.cfg.DBPath); err == nil {
		return nil
	}
	if err := u.copySeedDatabase(); err == nil {
		log.Info().Str("db_path", u.cfg.DBPath).Str("seed_path", u.cfg.SeedPath).Msg("geoip database seeded")
		return nil
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errSeedPathEmpty) {
		return err
	}
	if strings.TrimSpace(u.cfg.AccountID) == "" || strings.TrimSpace(u.cfg.LicenseKey) == "" {
		return errors.New("GeoLite2 database is missing and MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY are not set")
	}
	return u.download(ctx)
}

func (u *Updater) Run(ctx context.Context, mgr *Manager) {
	if u == nil || u.cfg.Interval <= 0 {
		return
	}

	t := time.NewTicker(u.cfg.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := u.checkAndUpdate(ctx, mgr); err != nil {
				log.Warn().Err(err).Msg("geoip update check failed")
			}
		}
	}
}

func (u *Updater) checkAndUpdate(ctx context.Context, mgr *Manager) error {
	if strings.TrimSpace(u.cfg.AccountID) == "" || strings.TrimSpace(u.cfg.LicenseKey) == "" {
		return errors.New("MAXMIND_ACCOUNT_ID/MAXMIND_LICENSE_KEY not set")
	}

	remoteLM, err := u.headLastModified(ctx)
	if err != nil {
		return err
	}
	localLM := ""
	if u.cfg.LastModifiedPath != "" {
		localLMBytes, _ := os.ReadFile(u.cfg.LastModifiedPath)
		localLM = strings.TrimSpace(string(localLMBytes))
	}
	if localLM != "" && localLM == remoteLM {
		log.Debug().Str("last_modified", remoteLM).Msg("geoip database up to date")
		return nil
	}

	if err := u.download(ctx); err != nil {
		return err
	}
	if err := mgr.Load(); err != nil {
		return err
	}
	if u.cfg.LastModifiedPath != "" {
		if err := os.MkdirAll(filepath.Dir(u.cfg.LastModifiedPath), 0o755); err != nil {
			return err
		}
		_ = os.WriteFile(u.cfg.LastModifiedPath, []byte(remoteLM), 0o600)
	}
	log.Info().Str("last_modified", remoteLM).Msg("geoip database updated")
	return nil
}

func (u *Updater) download(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- DownloadGeoLite2CityMMDB(
			u.cfg.DBPath,
			u.cfg.DownloadURL,
			u.cfg.AccountID,
			u.cfg.LicenseKey,
			u.cfg.HTTPTimeout,
		)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

var errSeedPathEmpty = errors.New("geoip seed path is empty")

func (u *Updater) copySeedDatabase() error {
	seedPath := strings.TrimSpace(u.cfg.SeedPath)
	if seedPath == "" {
		return errSeedPathEmpty
	}
	source, err := os.Open(seedPath)
	if err != nil {
		return err
	}
	defer source.Close()
	if err := os.MkdirAll(filepath.Dir(u.cfg.DBPath), 0o755); err != nil {
		return err
	}
	tempPath := u.cfg.DBPath + ".tmp"
	target, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := target.ReadFrom(source); err != nil {
		_ = target.Close()
		_ = os.Remove(tempPath)
		return err
	}
	if err := target.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return os.Rename(tempPath, u.cfg.DBPath)
}

func (u *Updater) headLastModified(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: u.cfg.HTTPTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.cfg.DownloadURL, nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(u.cfg.AccountID, u.cfg.LicenseKey)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("HEAD status %d", resp.StatusCode)
	}
	lm := resp.Header.Get("Last-Modified")
	if lm == "" {
		return "", errors.New("no Last-Modified header")
	}
	return lm, nil
}
