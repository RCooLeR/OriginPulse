package db

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"

	"originpulse/internal/config"
)

var ErrUnavailable = errors.New("database is not configured")
var ErrLockUnavailable = errors.New("maintenance lock is already held")

const migrationLockKey int64 = 7720007

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, cfg config.DatabaseConfig) (*Store, error) {
	url := strings.TrimSpace(cfg.URLValue())
	if url == "" {
		return &Store{}, nil
	}

	poolCfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = int32(cfg.MaxConns)
	}
	if poolCfg.ConnConfig.RuntimeParams == nil {
		poolCfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	if strings.TrimSpace(poolCfg.ConnConfig.RuntimeParams["application_name"]) == "" {
		poolCfg.ConnConfig.RuntimeParams["application_name"] = fmt.Sprintf("originpulse-%d", os.Getpid())
	}
	if strings.TrimSpace(poolCfg.ConnConfig.RuntimeParams["jit"]) == "" {
		poolCfg.ConnConfig.RuntimeParams["jit"] = "off"
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, err
	}

	return &Store{pool: pool}, nil
}

func (s *Store) Enabled() bool {
	return s != nil && s.pool != nil
}

func (s *Store) Pool() (*pgxpool.Pool, error) {
	if !s.Enabled() {
		return nil, ErrUnavailable
	}
	return s.pool, nil
}

func (s *Store) Close() {
	if s.Enabled() {
		s.pool.Close()
	}
}

func (s *Store) Ping(ctx context.Context) error {
	pool, err := s.Pool()
	if err != nil {
		return err
	}
	return pool.Ping(ctx)
}

func (s *Store) WithAdvisoryLock(ctx context.Context, key int64, fn func(context.Context) error) error {
	pool, err := s.Pool()
	if err != nil {
		return err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return ErrLockUnavailable
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
	}()

	return fn(ctx)
}

func (s *Store) Migrate(ctx context.Context) error {
	pool, err := s.Pool()
	if err != nil {
		return err
	}

	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return err
	}
	defer func() {
		_, _ = lockConn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()

	if _, err := pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
)`); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		return err
	}

	versions := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		versions = append(versions, entry.Name())
	}
	sort.Strings(versions)

	for _, version := range versions {
		applied, err := s.migrationApplied(ctx, version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		sqlBytes, err := migrationFiles.ReadFile("migrations/" + version)
		if err != nil {
			return err
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", version, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1) ON CONFLICT (version) DO NOTHING`, version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		log.Info().Str("migration", version).Msg("database migration applied")
	}

	return nil
}

func (s *Store) migrationApplied(ctx context.Context, version string) (bool, error) {
	pool, err := s.Pool()
	if err != nil {
		return false, err
	}

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}
