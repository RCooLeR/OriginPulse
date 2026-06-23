package sites

import (
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"

	"originpulse/internal/config"
	"originpulse/internal/db"
)

type Site struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	SourceType     string   `json:"source_type"`
	PantheonSiteID string   `json:"pantheon_site_id"`
	LocalPath      string   `json:"local_path"`
	FilenameMasks  []string `json:"filename_masks"`
	Enabled        bool     `json:"enabled"`
	Envs           []string `json:"envs"`
	Tags           []string `json:"tags"`
}

type Repository struct {
	db  *db.Store
	cfg config.Config
}

func NewRepository(store *db.Store, cfg config.Config) *Repository {
	return &Repository{db: store, cfg: cfg}
}

func (r *Repository) List(ctx context.Context) ([]Site, error) {
	if r.db == nil || !r.db.Enabled() {
		return fromConfig(r.cfg), nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return nil, err
	}

	rows, err := pool.Query(ctx, `
SELECT s.id, s.name, coalesce(s.source_type, 'pantheon'), coalesce(s.pantheon_site_id, ''), coalesce(s.local_path, ''),
       coalesce(s.filename_masks, '{}'), s.enabled, s.tags,
       coalesce(array_agg(se.env ORDER BY se.env) FILTER (WHERE se.enabled), '{}')
FROM sites s
LEFT JOIN site_envs se ON se.site_id = s.id
WHERE s.enabled = true
GROUP BY s.id, s.name, s.source_type, s.pantheon_site_id, s.local_path, s.filename_masks, s.enabled, s.tags
ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Site, 0)
	for rows.Next() {
		var site Site
		if err := rows.Scan(&site.ID, &site.Name, &site.SourceType, &site.PantheonSiteID, &site.LocalPath, &site.FilenameMasks, &site.Enabled, &site.Tags, &site.Envs); err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	return out, rows.Err()
}

func (r *Repository) SeedFromConfig(ctx context.Context) error {
	if r.db == nil || !r.db.Enabled() {
		return nil
	}

	pool, err := r.db.Pool()
	if err != nil {
		return err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	for _, site := range r.cfg.Sites {
		if site.ID == "" {
			continue
		}
		tags := site.Tags
		if tags == nil {
			tags = []string{}
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO sites (id, name, source_type, pantheon_site_id, local_path, filename_masks, enabled, tags)
VALUES ($1, $2, $3, nullif($4, ''), nullif($5, ''), $6, $7, $8)
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name,
    source_type = EXCLUDED.source_type,
    pantheon_site_id = EXCLUDED.pantheon_site_id,
    local_path = EXCLUDED.local_path,
    filename_masks = EXCLUDED.filename_masks,
    enabled = EXCLUDED.enabled,
    tags = EXCLUDED.tags,
    updated_at = now()`,
			site.ID, site.Name, site.SourceType, site.PantheonSiteID, site.LocalPath, site.FilenameMasks, site.Enabled, tags); err != nil {
			return err
		}

		envs := site.Envs
		if len(envs) == 0 {
			envs = r.cfg.Pantheon.DefaultEnvs
		}
		for _, env := range envs {
			if _, err := tx.Exec(ctx, `
INSERT INTO site_envs (site_id, env, enabled)
VALUES ($1, $2, true)
ON CONFLICT (site_id, env) DO UPDATE
SET enabled = EXCLUDED.enabled`,
				site.ID, env); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return err
	}
	return nil
}

func fromConfig(cfg config.Config) []Site {
	configSites := cfg.EnabledSites()
	out := make([]Site, 0, len(configSites))
	for _, site := range configSites {
		envs := site.Envs
		if len(envs) == 0 {
			envs = cfg.Pantheon.DefaultEnvs
		}
		out = append(out, Site{
			ID:             site.ID,
			Name:           site.Name,
			SourceType:     site.SourceType,
			PantheonSiteID: site.PantheonSiteID,
			LocalPath:      site.LocalPath,
			FilenameMasks:  append([]string(nil), site.FilenameMasks...),
			Enabled:        site.Enabled,
			Envs:           append([]string(nil), envs...),
			Tags:           append([]string(nil), site.Tags...),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}
