package pantheon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"

	"originpulse/internal/config"
	"originpulse/internal/jobs"
)

func (c *Collector) collectLocalSiteEnv(ctx context.Context, jobID string, site config.SiteConfig, env string) error {
	sourcePath, err := filepath.Abs(strings.TrimSpace(site.LocalPath))
	if err != nil {
		c.jobs.Finish(jobID, jobs.StatusFailed, "failed to resolve local log path", err)
		return err
	}

	sourceStep := c.jobs.StartStep(ctx, jobID, "scan local logs", map[string]any{
		"site_id": site.ID,
		"env":     env,
		"path":    sourcePath,
	})
	info, err := os.Stat(sourcePath)
	if err != nil {
		c.jobs.FinishStep(sourceStep, jobs.StatusFailed, "local log path is not readable", err, nil)
		c.jobs.Finish(jobID, jobs.StatusFailed, "local log path is not readable", err)
		log.Error().
			Err(err).
			Str("site_id", site.ID).
			Str("env", env).
			Str("source_path", sourcePath).
			Msg("local log path is not readable; skipping local site")
		return nil
	}
	if !info.IsDir() {
		err := fmt.Errorf("local log path %q is not a directory", sourcePath)
		c.jobs.FinishStep(sourceStep, jobs.StatusFailed, "local log path is not a directory", err, nil)
		c.jobs.Finish(jobID, jobs.StatusFailed, "local log path is not a directory", err)
		log.Error().
			Err(err).
			Str("site_id", site.ID).
			Str("env", env).
			Str("source_path", sourcePath).
			Msg("local log path is not a directory; skipping local site")
		return nil
	}

	rawFiles, err := c.discoverLocalRawFiles(sourcePath, site, env)
	if err != nil {
		c.jobs.FinishStep(sourceStep, jobs.StatusFailed, "local log scan failed", err, nil)
		c.jobs.Finish(jobID, jobs.StatusFailed, "local log scan failed", err)
		return err
	}
	c.jobs.FinishStep(sourceStep, jobs.StatusSuccess, "local log scan completed", nil, map[string]any{
		"files_seen": len(rawFiles),
	})

	var stats DownloadStats
	stats.ServersAttempted = 1
	stats.ServersSucceeded = 1
	stats.FilesSeen = len(rawFiles)

	for _, rawFile := range rawFiles {
		shouldDownload := true
		if c.rawFiles != nil {
			discoverStep := c.jobs.StartStep(ctx, jobID, "register local file", fileStepMeta(map[string]any{
				"site_id":      site.ID,
				"env":          env,
				"source_type":  "local",
				"container_id": rawFile.ContainerID,
			}, rawFile))
			if err := c.rawFiles.MarkDiscovered(ctx, rawFile); err != nil {
				c.jobs.FinishStep(discoverStep, jobs.StatusFailed, "failed to register local file", err, nil)
				c.jobs.Finish(jobID, jobs.StatusFailed, "failed to register local file", err)
				return err
			}
			c.jobs.FinishStep(discoverStep, jobs.StatusSuccess, "local file registered", nil, nil)

			decisionStep := c.jobs.StartStep(ctx, jobID, "check copy need", fileStepMeta(map[string]any{
				"site_id":      site.ID,
				"env":          env,
				"source_type":  "local",
				"container_id": rawFile.ContainerID,
			}, rawFile))
			var err error
			shouldDownload, err = c.rawFiles.ShouldDownload(ctx, rawFile)
			if err != nil {
				c.jobs.FinishStep(decisionStep, jobs.StatusFailed, "copy decision failed", err, nil)
				c.jobs.Finish(jobID, jobs.StatusFailed, "copy decision failed", err)
				return err
			}
			c.jobs.FinishStep(decisionStep, jobs.StatusSuccess, downloadDecisionMessage(shouldDownload), nil, map[string]any{"should_download": shouldDownload})
		}

		if !shouldDownload && localFileMatches(rawFile.LocalPath, rawFile.RemoteSize) {
			stats.FilesSkipped++
			step := c.jobs.StartStep(ctx, jobID, "copy local file", fileStepMeta(map[string]any{
				"site_id":      site.ID,
				"env":          env,
				"source_type":  "local",
				"container_id": rawFile.ContainerID,
			}, rawFile))
			c.jobs.FinishStep(step, jobs.StatusSkipped, "file already current", nil, map[string]any{"downloaded": false})
			continue
		}

		step := c.jobs.StartStep(ctx, jobID, "copy local file", fileStepMeta(map[string]any{
			"site_id":      site.ID,
			"env":          env,
			"source_type":  "local",
			"container_id": rawFile.ContainerID,
		}, rawFile))
		sha, written, err := copyLocalFile(ctx, rawFile.RemotePath, rawFile.LocalPath)
		if err != nil {
			if c.rawFiles != nil {
				_ = c.rawFiles.MarkFailed(ctx, rawFile, err)
			}
			c.jobs.FinishStep(step, jobs.StatusFailed, "local file copy failed", err, map[string]any{"bytes_written": written})
			c.jobs.Finish(jobID, jobs.StatusFailed, "local file copy failed", err)
			return err
		}
		rawFile.SHA256 = sha
		if c.rawFiles != nil {
			markStep := c.jobs.StartStep(ctx, jobID, "mark local file copied", fileStepMeta(map[string]any{
				"site_id":      site.ID,
				"env":          env,
				"source_type":  "local",
				"container_id": rawFile.ContainerID,
			}, rawFile))
			if err := c.rawFiles.MarkDownloaded(ctx, rawFile); err != nil {
				c.jobs.FinishStep(markStep, jobs.StatusFailed, "failed to mark local file copied", err, nil)
				c.jobs.Finish(jobID, jobs.StatusFailed, "failed to mark local file copied", err)
				return err
			}
			c.jobs.FinishStep(markStep, jobs.StatusSuccess, "local file marked copied", nil, nil)
		}
		stats.FilesDownloaded++
		stats.BytesDownloaded += written
		c.jobs.FinishStep(step, jobs.StatusSuccess, "local file copied", nil, map[string]any{
			"bytes_written": written,
			"sha256":        sha,
			"downloaded":    true,
		})
	}

	log.Info().
		Str("site_id", site.ID).
		Str("env", env).
		Str("source_path", sourcePath).
		Int("files_seen", stats.FilesSeen).
		Int("files_downloaded", stats.FilesDownloaded).
		Int("files_skipped", stats.FilesSkipped).
		Int64("bytes_downloaded", stats.BytesDownloaded).
		Msg("local log collection completed")

	c.jobs.FinishWithMeta(jobID, jobs.StatusSuccess, fmt.Sprintf("copied %d files, skipped %d", stats.FilesDownloaded, stats.FilesSkipped), nil, map[string]any{
		"files_seen":       stats.FilesSeen,
		"files_downloaded": stats.FilesDownloaded,
		"files_skipped":    stats.FilesSkipped,
		"bytes_downloaded": stats.BytesDownloaded,
		"source_type":      "local",
		"source_path":      sourcePath,
	})
	return nil
}

func (c *Collector) discoverLocalRawFiles(sourcePath string, site config.SiteConfig, env string) ([]RawFile, error) {
	rawFiles := []RawFile{}
	err := filepath.WalkDir(sourcePath, func(pathValue string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !matchesLocalFilenameMasks(entry.Name(), site.FilenameMasks) {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		logType := DetectLocalLogType(pathValue)
		if !shouldCollectLocalLogType(c.cfg.Collection.LogTypes, logType) {
			return nil
		}
		rel, err := filepath.Rel(sourcePath, pathValue)
		if err != nil {
			return err
		}
		remotePath := filepath.ToSlash(rel)
		rawFiles = append(rawFiles, RawFile{
			SiteID:      site.ID,
			Env:         env,
			ContainerID: "local",
			LogType:     logType,
			RemotePath:  pathValue,
			RemoteSize:  info.Size(),
			RemoteMTime: info.ModTime().UTC(),
			LocalPath:   LocalRawPath(c.cfg.RawDir(), site.ID, env, "local", remotePath),
		})
		return nil
	})
	return rawFiles, err
}

func matchesLocalFilenameMasks(name string, masks []string) bool {
	if len(masks) == 0 {
		return true
	}
	for _, mask := range masks {
		matched, err := filepath.Match(mask, name)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func shouldCollectLocalLogType(logTypes []string, logType string) bool {
	if logType == "unknown" {
		return false
	}
	for _, allowed := range logTypes {
		if allowed == logType {
			return true
		}
	}
	return false
}

func copyLocalFile(ctx context.Context, sourcePath string, localPath string) (string, int64, error) {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return "", 0, err
	}
	defer sourceFile.Close()

	if err := os.MkdirAll(filepath.Dir(localPath), 0o750); err != nil {
		return "", 0, err
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", localPath, os.Getpid())
	localFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return "", 0, err
	}

	hasher := sha256.New()
	written, copyErr := copyWithContext(ctx, io.MultiWriter(localFile, hasher), sourceFile)
	syncErr := localFile.Sync()
	closeErr := localFile.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, copyErr
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return "", written, closeErr
	}
	if err := replaceLocalFile(tmpPath, localPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", written, err
	}
	return hex.EncodeToString(hasher.Sum(nil)), written, nil
}
