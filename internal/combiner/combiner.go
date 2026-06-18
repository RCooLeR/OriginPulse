package combiner

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"originpulse/internal/config"
	"originpulse/internal/parser"
)

type Options struct {
	LogType string
	From    time.Time
	To      time.Time
	Force   bool
}

type Result struct {
	SegmentsWritten  int               `json:"segments_written"`
	LinesCombined    int               `json:"lines_combined"`
	LinesQuarantined int               `json:"lines_quarantined"`
	Segments         []SegmentManifest `json:"segments"`
}

type CombinedLine struct {
	TS          string `json:"ts"`
	SiteID      string `json:"site_id"`
	Env         string `json:"env"`
	ContainerID string `json:"container_id"`
	LogType     string `json:"log_type"`
	Raw         string `json:"raw"`
	Fingerprint string `json:"fingerprint"`
}

type entry struct {
	TS          time.Time
	SiteID      string
	Env         string
	ContainerID string
	LogType     string
	Raw         string
	Fingerprint string
}

type Service struct {
	cfg  config.Config
	repo *Repository
}

func NewService(cfg config.Config, repo *Repository) *Service {
	return &Service{cfg: cfg, repo: repo}
}

func (s *Service) Combine(ctx context.Context, opts Options) (Result, error) {
	if opts.LogType == "" {
		opts.LogType = "nginx-access"
	}
	if opts.From.IsZero() || opts.To.IsZero() || !opts.From.Before(opts.To) {
		return Result{}, fmt.Errorf("combine requires a valid --from and --to range")
	}

	sources, err := s.sources(ctx, opts)
	if err != nil {
		return Result{}, err
	}

	buckets := map[time.Time]map[string]entry{}
	result := Result{}
	for _, source := range sources {
		if err := s.readSource(ctx, source, opts, buckets, &result); err != nil {
			return result, err
		}
	}

	bucketStarts := make([]time.Time, 0, len(buckets))
	for bucketStart := range buckets {
		bucketStarts = append(bucketStarts, bucketStart)
	}
	sort.Slice(bucketStarts, func(i, j int) bool {
		return bucketStarts[i].Before(bucketStarts[j])
	})

	for _, bucketStart := range bucketStarts {
		entries := make([]entry, 0, len(buckets[bucketStart]))
		for _, item := range buckets[bucketStart] {
			entries = append(entries, item)
		}
		sort.Slice(entries, func(i, j int) bool {
			if !entries[i].TS.Equal(entries[j].TS) {
				return entries[i].TS.Before(entries[j].TS)
			}
			if entries[i].SiteID != entries[j].SiteID {
				return entries[i].SiteID < entries[j].SiteID
			}
			if entries[i].Env != entries[j].Env {
				return entries[i].Env < entries[j].Env
			}
			if entries[i].ContainerID != entries[j].ContainerID {
				return entries[i].ContainerID < entries[j].ContainerID
			}
			return entries[i].Fingerprint < entries[j].Fingerprint
		})

		manifest, err := s.writeSegment(ctx, opts.LogType, bucketStart, entries)
		if err != nil {
			return result, err
		}
		result.SegmentsWritten++
		result.LinesCombined += len(entries)
		result.Segments = append(result.Segments, manifest)
	}

	return result, nil
}

func (s *Service) sources(ctx context.Context, opts Options) ([]RawSource, error) {
	if s.repo != nil && s.repo.Enabled() {
		modifiedSince := time.Time{}
		if !opts.From.IsZero() {
			modifiedSince = opts.From.Add(-15 * time.Minute)
		}
		return s.repo.DownloadedRawSources(ctx, opts.LogType, modifiedSince)
	}
	return s.sourcesFromFilesystem(opts.LogType)
}

func (s *Service) sourcesFromFilesystem(logType string) ([]RawSource, error) {
	rawDir := s.cfg.RawDir()
	sources := make([]RawSource, 0)
	err := filepath.WalkDir(rawDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if detectLogType(path) != logType {
			return nil
		}

		rel, err := filepath.Rel(rawDir, path)
		if err != nil {
			return err
		}
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) < 5 {
			return nil
		}
		sources = append(sources, RawSource{
			SiteID:      parts[0],
			Env:         parts[1],
			ContainerID: parts[2],
			LogType:     logType,
			LocalPath:   path,
		})
		return nil
	})
	if os.IsNotExist(err) {
		return sources, nil
	}
	return sources, err
}

func (s *Service) readSource(ctx context.Context, source RawSource, opts Options, buckets map[time.Time]map[string]entry, result *Result) error {
	reader, closer, err := openPossiblyGzip(source.LocalPath)
	if err != nil {
		return err
	}
	defer closer()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 128*1024), 10*1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		raw := strings.TrimRight(scanner.Text(), "\r")
		if raw == "" {
			continue
		}

		ts, err := parser.ParseAccessTimestamp(raw)
		if err != nil {
			result.LinesQuarantined++
			if qErr := s.quarantine(source, "timestamp_parse_failed", raw); qErr != nil {
				return qErr
			}
			continue
		}
		if ts.Before(opts.From) || !ts.Before(opts.To) {
			continue
		}

		fp := fingerprint(source, ts, raw)
		bucketStart := ts.Truncate(time.Hour)
		if buckets[bucketStart] == nil {
			buckets[bucketStart] = map[string]entry{}
		}
		buckets[bucketStart][fp] = entry{
			TS:          ts,
			SiteID:      source.SiteID,
			Env:         source.Env,
			ContainerID: source.ContainerID,
			LogType:     source.LogType,
			Raw:         raw,
			Fingerprint: fp,
		}
	}
	return scanner.Err()
}

func (s *Service) writeSegment(ctx context.Context, logType string, bucketStart time.Time, entries []entry) (SegmentManifest, error) {
	bucketStart = bucketStart.UTC().Truncate(time.Hour)
	bucketEnd := bucketStart.Add(time.Hour)
	finalPath := filepath.Join(
		s.cfg.CombinedDir(),
		logType,
		bucketStart.Format("2006"),
		bucketStart.Format("01"),
		bucketStart.Format("02"),
		bucketStart.Format("15")+".log.gz",
	)
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o750); err != nil {
		return SegmentManifest{}, err
	}
	tmpPath := fmt.Sprintf("%s.tmp.%d", finalPath, time.Now().UnixNano())

	outFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return SegmentManifest{}, err
	}

	hasher := sha256.New()
	count, minTS, maxTS, writeErr := writeGzipJSONL(ctx, io.MultiWriter(outFile, hasher), entries)
	syncErr := outFile.Sync()
	closeErr := outFile.Close()
	if writeErr != nil {
		_ = os.Remove(tmpPath)
		return SegmentManifest{}, writeErr
	}
	if syncErr != nil {
		_ = os.Remove(tmpPath)
		return SegmentManifest{}, syncErr
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return SegmentManifest{}, closeErr
	}

	if err := replaceFile(tmpPath, finalPath); err != nil {
		_ = os.Remove(tmpPath)
		return SegmentManifest{}, err
	}

	manifest := SegmentManifest{
		LogType:     logType,
		BucketStart: bucketStart,
		BucketEnd:   bucketEnd,
		Path:        finalPath,
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
		LineCount:   int64(count),
		MinTS:       minTS,
		MaxTS:       maxTS,
		Status:      statusForBucket(bucketEnd, s.cfg.Combiner.FinalizeAfter),
	}
	if s.repo != nil {
		if err := s.repo.UpsertSegment(ctx, manifest); err != nil {
			return manifest, err
		}
	}
	return manifest, nil
}

func writeGzipJSONL(ctx context.Context, writer io.Writer, entries []entry) (int, *time.Time, *time.Time, error) {
	gzipWriter, err := gzip.NewWriterLevel(writer, gzip.BestCompression)
	if err != nil {
		return 0, nil, nil, err
	}
	gzipWriter.Name = "combined.jsonl"
	gzipWriter.ModTime = time.Unix(0, 0).UTC()

	encoder := json.NewEncoder(gzipWriter)
	var minTS *time.Time
	var maxTS *time.Time
	for i, item := range entries {
		select {
		case <-ctx.Done():
			_ = gzipWriter.Close()
			return i, minTS, maxTS, ctx.Err()
		default:
		}

		ts := item.TS.UTC()
		if minTS == nil || ts.Before(*minTS) {
			copy := ts
			minTS = &copy
		}
		if maxTS == nil || ts.After(*maxTS) {
			copy := ts
			maxTS = &copy
		}
		line := CombinedLine{
			TS:          ts.Format(time.RFC3339Nano),
			SiteID:      item.SiteID,
			Env:         item.Env,
			ContainerID: item.ContainerID,
			LogType:     item.LogType,
			Raw:         item.Raw,
			Fingerprint: item.Fingerprint,
		}
		if err := encoder.Encode(line); err != nil {
			_ = gzipWriter.Close()
			return i, minTS, maxTS, err
		}
	}
	if err := gzipWriter.Close(); err != nil {
		return len(entries), minTS, maxTS, err
	}
	return len(entries), minTS, maxTS, nil
}

func (s *Service) quarantine(source RawSource, reason string, raw string) error {
	now := time.Now().UTC()
	path := filepath.Join(s.cfg.QuarantineDir(), source.LogType, now.Format("2006-01-02")+"-unparsed.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer file.Close()

	record := map[string]string{
		"site_id":      source.SiteID,
		"env":          source.Env,
		"container_id": source.ContainerID,
		"log_type":     source.LogType,
		"source_file":  source.LocalPath,
		"reason":       reason,
		"raw":          raw,
	}
	encoder := json.NewEncoder(file)
	return encoder.Encode(record)
}

func fingerprint(source RawSource, ts time.Time, raw string) string {
	rawHash := sha256Hex(raw)
	input := source.SiteID + "\x00" +
		source.Env + "\x00" +
		source.ContainerID + "\x00" +
		source.LogType + "\x00" +
		ts.UTC().Format(time.RFC3339Nano) + "\x00" +
		rawHash
	return sha256Hex(input)
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func openPossiblyGzip(path string) (io.Reader, func() error, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			_ = file.Close()
			return nil, nil, err
		}
		return gzipReader, func() error {
			gzErr := gzipReader.Close()
			fileErr := file.Close()
			if gzErr != nil {
				return gzErr
			}
			return fileErr
		}, nil
	}
	return file, file.Close, nil
}

func detectLogType(path string) string {
	lower := strings.ToLower(filepath.Base(path))
	lower = strings.TrimSuffix(lower, ".gz")
	switch {
	case strings.HasPrefix(lower, "nginx-access.log"):
		return "nginx-access"
	case strings.HasPrefix(lower, "nginx-error.log"):
		return "nginx-error"
	case strings.HasPrefix(lower, "php-error.log"):
		return "php-error"
	default:
		return "unknown"
	}
}

func statusForBucket(bucketEnd time.Time, finalizeAfter time.Duration) string {
	if time.Now().UTC().After(bucketEnd.Add(finalizeAfter)) {
		return "finalized"
	}
	return "rewritten"
}

func replaceFile(tmpPath string, finalPath string) error {
	if err := os.Rename(tmpPath, finalPath); err == nil {
		return nil
	}
	if err := os.Remove(finalPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(tmpPath, finalPath)
}
