# Configuration

OriginPulse reads YAML configuration from `config.yml` by default. `config.example.yml` is safe for Git and should be used as the template. Keep real `config.yml` out of source control.

## Server And App

```yaml
server:
  addr: ":8080"

app:
  name: "OriginPulse"
  data_dir: "./data"
  log_level: "info"
```

`app.data_dir` is the base directory for raw files, combined segments, archives, and runtime GeoIP files unless specific paths override it.

## Database

```yaml
database:
  url_env: "DATABASE_URL"
  auto_migrate: true
  seed_config_sites: true
  max_conns: 10
```

`DATABASE_URL` must point to PostgreSQL 18 or newer because current migrations use
the built-in `uuidv7()` function. Automatic migrations are enabled by default.
Back up and upgrade older PostgreSQL installations before starting this version.
`max_conns` must be at least 2 so maintenance work can use the pool while its
dedicated advisory-lock connection is held.

## Auth

```yaml
auth:
  session_cookie_name: "originpulse_session"
  session_ttl: "168h"
  secure_cookies: false
```

Set `secure_cookies: true` when serving through HTTPS.

## Ollama

```yaml
ollama:
  base_url_env: "OLLAMA_BASE_URL"
  model_env: "OLLAMA_MODEL"
  timeout_env: "OLLAMA_TIMEOUT"
  timeout: "10m"
```

`OLLAMA_TIMEOUT` controls how long report generation waits for Ollama. CPU-only servers may need a longer value such as `20m`.

## Collection

```yaml
collection:
  enabled: false
  interval: "6m"
  timeout_per_site: "16m"
  server_lock_cooldown: "15m"
  max_parallel_sites: 2
  log_types:
    - "nginx-access"
    - "nginx-error"
    - "apache-access"
    - "apache-error"
    - "php-error"
    - "php-slow"
    - "mysql"
    - "mysql-slow"
  raw_dir: "./data/raw"
```

Collection can run on a schedule or manually through the UI/API/CLI.

## Pantheon

```yaml
pantheon:
  default_envs: ["live"]
  sftp_port: 2222
  dns_timeout: "10s"
  ssh:
    private_key_path_env: "PANTHEON_SSH_KEY_PATH"
    private_key_path: ""
    known_hosts_path_env: "PANTHEON_KNOWN_HOSTS_PATH"
    known_hosts_path: ""
    auto_update_host_keys_env: "PANTHEON_AUTO_UPDATE_HOST_KEYS"
    auto_update_host_keys: false
    insecure_ignore_host_key: false
    allow_legacy_rsa: false
```

The Docker Compose file mounts both the private key and a `known_hosts`
file into the API and collector and exposes their container paths through
`PANTHEON_SSH_KEY_PATH` and `PANTHEON_KNOWN_HOSTS_PATH`. Set the host-file paths
with `PANTHEON_SSH_KEY_FILE` and `PANTHEON_KNOWN_HOSTS_FILE` in `docker/.env`.
Compose defaults `PANTHEON_AUTO_UPDATE_HOST_KEYS` to `true`, which overrides
`auto_update_host_keys` from YAML. Automatic mode accepts and records new keys
and replaces changed keys under `app.data_dir/ssh/known_hosts.d/`, one file per
server IP and port. The records survive container restarts and recreation. This
mode trusts presented keys without checking them against the mounted file.

Set `PANTHEON_AUTO_UPDATE_HOST_KEYS=false` to verify against `known_hosts` instead.
In that mode, host verification fails closed when neither a known-hosts file nor
the `insecure_ignore_host_key` compatibility switch is configured. Enable
`allow_legacy_rsa` only for a Pantheon account or host that cannot negotiate
RSA-SHA2.

Older config files that omit the two compatibility switches retain the previous
host-key and RSA behavior so upgrades do not silently break collection. Add the
explicit `false` values above, disable automatic updates, and provide a verified
known-hosts file to require host verification.

## Sites

Pantheon site:

```yaml
sites:
  - id: "example-site"
    name: "Example Site"
    source_type: "pantheon"
    pantheon_site_id: "12345678-1234-1234-abcd-0123456789ab"
    enabled: true
    envs: ["live"]
```

Local log site:

```yaml
sites:
  - id: "example-apache"
    name: "Example Apache Logs"
    source_type: "local"
    local_path: "./tmp/example.com"
    filename_masks:
      - "example-*"
    enabled: true
    envs: ["live"]
```

Site IDs should be stable and non-sensitive. Use tags for grouping.

## Pipeline

```yaml
combiner:
  combined_dir: "./data/combined"
  quarantine_dir: "./data/quarantine"
  settling_window: "5m"
  finalize_after: "15m"

pipeline:
  index_workers: 3
  max_segments: 500
```

The settling window prevents active files from being combined too early.

## Retention

Defaults keep hot indexed events for 60 days, raw files for 14 days, daily archives after 7 days, weekly archives after 30 days, and compressed archives for 90 days.

See [Storage And Retention](storage-and-retention.md).

## GeoIP And IP Intelligence

GeoIP loads from `GEOIP_DB_PATH`, the configured `geoip.db_path`, or the bundled seed. MaxMind credentials can be supplied for updates.

IP intelligence runs every `ip_intel.interval`, can backfill on startup, and uses official provider ranges plus local evidence.

## Notifications

SMTP credentials are read from environment variables. Browser push uses VAPID keys generated by:

```powershell
originpulse web-push-keys
```

Webhook URLs can be supplied through `ORIGINPULSE_PUSH_WEBHOOK_URLS`.

## Manual IP Allowlist

```yaml
ip_allowlist:
  enabled: true
  entries:
    - value: "203.0.113.10"
      label: "Corporate VPN"
      actor_type: "corporate-vpn"
      source: "manual"
```

Manual allowlist entries render as trusted sources. Keep this list small and intentional.
