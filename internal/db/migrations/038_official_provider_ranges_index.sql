CREATE INDEX IF NOT EXISTS official_provider_ranges_cidr_gist_idx
  ON official_provider_ranges USING gist (cidr inet_ops);
