CREATE TABLE IF NOT EXISTS official_provider_ranges (
  provider_id text NOT NULL,
  provider_name text NOT NULL,
  actor_type text NOT NULL DEFAULT 'crawler',
  cidr cidr NOT NULL,
  source_url text NOT NULL,
  fetched_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (provider_id, cidr)
);

ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS provider_verified boolean NOT NULL DEFAULT false;
ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS provider_id text;
ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS provider_name text;
ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS provider_source_url text;
ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS provider_range cidr;
ALTER TABLE ip_intel ADD COLUMN IF NOT EXISTS provider_refreshed_at timestamptz;
