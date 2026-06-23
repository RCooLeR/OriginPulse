package pantheon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"originpulse/internal/config"
	"originpulse/internal/jobs"
)

type fakeLogDownloader struct {
	mu     sync.Mutex
	errs   map[string]error
	calls  map[string]int
	stats  map[string]DownloadStats
	seenID map[string]string
}

func (f *fakeLogDownloader) DownloadLogs(ctx context.Context, jobID string, target Target, serverKind string, serverAddress string, containerID string, repo *RawFileRepository) (DownloadStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	if f.seenID == nil {
		f.seenID = make(map[string]string)
	}
	f.calls[serverAddress]++
	f.seenID[serverAddress] = containerID
	if f.stats != nil {
		if stats, ok := f.stats[serverAddress]; ok {
			return stats, f.errs[serverAddress]
		}
	}
	return DownloadStats{FilesSeen: 1, FilesSkipped: 1}, f.errs[serverAddress]
}

func (f *fakeLogDownloader) callCount(serverAddress string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[serverAddress]
}

func TestDownloadTargetLogsCooldownSkipsOnlyLockedServer(t *testing.T) {
	ctx := context.Background()
	cfg := config.Config{}
	cfg.Collection.ServerLockCooldown = time.Hour
	collector := NewCollector(cfg, jobs.NewStore(20), nil)

	lockedIP := "34.67.175.247"
	healthyIP := "146.148.78.169"
	downloader := &fakeLogDownloader{
		errs: map[string]error{
			lockedIP: errors.New("ssh: rejected: administratively prohibited (Pantheon: The requested resource is locked.)"),
		},
	}
	collector.downloader = downloader

	target := Target{
		SiteID:       "example-site",
		Environment:  "live",
		AppserverIPs: []string{lockedIP, healthyIP},
	}

	stats, err := collector.downloadTargetLogs(ctx, "job-lock", target)
	if err != nil {
		t.Fatalf("first download should keep partial collection successful: %v", err)
	}
	if stats.ServersAttempted != 2 || stats.ServersSucceeded != 1 || stats.ServersLocked != 1 || stats.ServersFailed != 0 || stats.ServersSkipped != 0 {
		t.Fatalf("unexpected first stats: %+v", stats)
	}
	if got := downloader.callCount(lockedIP); got != 1 {
		t.Fatalf("locked server first call count = %d, want 1", got)
	}
	if got := downloader.callCount(healthyIP); got != 1 {
		t.Fatalf("healthy server first call count = %d, want 1", got)
	}

	stats, err = collector.downloadTargetLogs(ctx, "job-skip", target)
	if err != nil {
		t.Fatalf("cooldown skip should keep partial collection successful: %v", err)
	}
	if stats.ServersAttempted != 1 || stats.ServersSucceeded != 1 || stats.ServersLocked != 0 || stats.ServersFailed != 0 || stats.ServersSkipped != 1 {
		t.Fatalf("unexpected cooldown stats: %+v", stats)
	}
	if got := downloader.callCount(lockedIP); got != 1 {
		t.Fatalf("locked server should not be called during cooldown, got %d calls", got)
	}
	if got := downloader.callCount(healthyIP); got != 2 {
		t.Fatalf("healthy server should still be collected, got %d calls", got)
	}
}
