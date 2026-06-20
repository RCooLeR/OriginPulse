package archiveimport

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/klauspost/compress/zstd"

	"originpulse/internal/config"
	"originpulse/internal/db"
	"originpulse/internal/indexer"
)

const importLockKey int64 = 7720006

type Options struct {
	ArchiveID   string `json:"archive_id"`
	ArchivePath string `json:"archive_path"`
	Reason      string `json:"reason"`
}

type Result struct {
	TemporaryImportID string                          `json:"temporary_import_id"`
	ArchiveID         string                          `json:"archive_id,omitempty"`
	ArchivePath       string                          `json:"archive_path"`
	ExpiresAt         time.Time                       `json:"expires_at"`
	RangeStart        time.Time                       `json:"range_start"`
	RangeEnd          time.Time                       `json:"range_end"`
	FilesImported     int                             `json:"files_imported"`
	EventsSeen        int                             `json:"events_seen"`
	ValidEvents       int                             `json:"valid_events"`
	InvalidEvents     int                             `json:"invalid_events"`
	EventsInserted    int                             `json:"events_inserted"`
	EventsConflicted  int                             `json:"events_conflicted"`
	EventsSkipped     int                             `json:"events_skipped"`
	RollupsUpdated    int                             `json:"rollups_updated"`
	SecurityProbes    int                             `json:"security_probes"`
	ErrorEvents       int                             `json:"error_events"`
	SlowRequestEvents int                             `json:"slow_request_events"`
	Sources           []indexer.TemporaryImportResult `json:"sources"`
}

type Service struct {
	cfg     config.Config
	db      *db.Store
	indexer *indexer.Service
}

type archiveRecord struct {
	ID         string
	Path       string
	RangeStart time.Time
	RangeEnd   time.Time
}

func NewService(cfg config.Config, store *db.Store, indexerService *indexer.Service) *Service {
	return &Service{cfg: cfg, db: store, indexer: indexerService}
}

func (s *Service) Enabled() bool {
	return s != nil && s.db != nil && s.db.Enabled() && s.indexer != nil
}

func (s *Service) Import(ctx context.Context, opts Options) (Result, error) {
	if !s.Enabled() {
		return Result{}, db.ErrUnavailable
	}
	pool, err := s.db.Pool()
	if err != nil {
		return Result{}, err
	}
	record, err := resolveArchive(ctx, pool, opts)
	if err != nil {
		return Result{}, err
	}
	if record.Path == "" {
		return Result{}, errors.New("archive path is empty")
	}
	if _, err := os.Stat(record.Path); err != nil {
		return Result{}, err
	}

	var result Result
	err = s.db.WithAdvisoryLock(ctx, importLockKey, func(ctx context.Context) error {
		expiresAt := time.Now().UTC().Add(s.cfg.Retention.TemporaryImportMaxAge)
		importID, err := createTemporaryImport(ctx, pool, opts, record, expiresAt)
		if err != nil {
			return err
		}
		result = Result{
			TemporaryImportID: importID,
			ArchiveID:         record.ID,
			ArchivePath:       record.Path,
			ExpiresAt:         expiresAt,
			RangeStart:        record.RangeStart,
			RangeEnd:          record.RangeEnd,
			Sources:           []indexer.TemporaryImportResult{},
		}
		if err := s.importArchive(ctx, record, importID, expiresAt, &result); err != nil {
			_ = markTemporaryImportFailed(context.Background(), pool, importID, err)
			return err
		}
		return markTemporaryImportImported(ctx, pool, result)
	})
	return result, err
}

func resolveArchive(ctx context.Context, pool *pgxpool.Pool, opts Options) (archiveRecord, error) {
	var record archiveRecord
	archiveID := strings.TrimSpace(opts.ArchiveID)
	archivePath := strings.TrimSpace(opts.ArchivePath)
	if archiveID == "" && archivePath == "" {
		return record, errors.New("archive id or archive path is required")
	}
	var err error
	if archiveID != "" {
		err = pool.QueryRow(ctx, `
SELECT id::text, path, range_start, range_end
FROM log_archives
WHERE id = $1::uuid
  AND status = 'ready'`, archiveID).Scan(&record.ID, &record.Path, &record.RangeStart, &record.RangeEnd)
	} else {
		abs, absErr := filepath.Abs(archivePath)
		if absErr == nil {
			archivePath = abs
		}
		err = pool.QueryRow(ctx, `
SELECT id::text, path, range_start, range_end
FROM log_archives
WHERE path = $1
  AND status = 'ready'`, archivePath).Scan(&record.ID, &record.Path, &record.RangeStart, &record.RangeEnd)
	}
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return record, errors.New("ready archive record not found")
		}
		return record, err
	}
	return record, nil
}

func createTemporaryImport(ctx context.Context, pool *pgxpool.Pool, opts Options, record archiveRecord, expiresAt time.Time) (string, error) {
	reason := strings.TrimSpace(opts.Reason)
	if reason == "" {
		reason = "manual archive import"
	}
	var importID string
	err := pool.QueryRow(ctx, `
INSERT INTO temporary_imports (
  reason, range_start, range_end, archive_paths, status, expires_at
) VALUES (
  $1, $2, $3, $4, 'importing', $5
)
RETURNING id::text`, reason, record.RangeStart, record.RangeEnd, []string{record.Path}, expiresAt).Scan(&importID)
	return importID, err
}

func (s *Service) importArchive(ctx context.Context, record archiveRecord, importID string, expiresAt time.Time, result *Result) error {
	file, err := os.Open(record.Path)
	if err != nil {
		return err
	}
	defer file.Close()

	zstdReader, err := zstd.NewReader(file)
	if err != nil {
		return err
	}
	defer zstdReader.Close()

	tarReader := tar.NewReader(zstdReader)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".gz") {
			continue
		}
		sourceName := header.Name
		item, err := s.indexer.ImportTemporaryCombinedGzip(ctx, indexer.TemporaryImportOptions{
			SourceName:        sourceName,
			Reader:            tarReader,
			TemporaryImportID: importID,
			ImportedUntil:     expiresAt,
		})
		if err != nil {
			return fmt.Errorf("import %s: %w", sourceName, err)
		}
		result.FilesImported++
		result.EventsSeen += item.EventsSeen
		result.ValidEvents += item.ValidEvents
		result.InvalidEvents += item.InvalidEvents
		result.EventsInserted += item.EventsInserted
		result.EventsConflicted += item.EventsConflicted
		result.EventsSkipped += item.EventsSkipped
		result.RollupsUpdated += item.RollupsUpdated
		result.SecurityProbes += item.SecurityProbes
		result.ErrorEvents += item.ErrorEvents
		result.SlowRequestEvents += item.SlowRequestEvents
		result.Sources = append(result.Sources, item)
	}
	return nil
}

func markTemporaryImportImported(ctx context.Context, pool *pgxpool.Pool, result Result) error {
	_, err := pool.Exec(ctx, `
UPDATE temporary_imports
SET status = 'imported',
    source_file_count = $2,
    imported_event_count = $3,
    conflicted_event_count = $4,
    invalid_event_count = $5,
    security_probe_count = $6,
    last_error = NULL
WHERE id = $1::uuid`,
		result.TemporaryImportID,
		result.FilesImported,
		result.EventsInserted,
		result.EventsConflicted,
		result.InvalidEvents,
		result.SecurityProbes,
	)
	return err
}

func markTemporaryImportFailed(ctx context.Context, pool *pgxpool.Pool, importID string, importErr error) error {
	_, err := pool.Exec(ctx, `
UPDATE temporary_imports
SET status = 'failed',
    last_error = $2
WHERE id = $1::uuid`, importID, importErr.Error())
	return err
}
