CREATE TABLE IF NOT EXISTS pantheon_server_cooldowns (
  site_id text NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  env text NOT NULL,
  server_kind text NOT NULL,
  server_ip text NOT NULL,
  cooldown_until timestamptz NOT NULL,
  reason text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (site_id, env, server_kind, server_ip)
);

CREATE INDEX IF NOT EXISTS pantheon_server_cooldowns_until_idx
  ON pantheon_server_cooldowns (cooldown_until);
