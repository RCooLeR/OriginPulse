# Config Model

## Goals

Config must support:

- multiple Pantheon sites
- multiple environments per site
- SFTP credentials
- storage locations
- collection schedules
- alert thresholds
- IP intelligence providers
- Ollama model settings
- notification targets

## Example `config.yml`

```yaml
app:
  public_url: "http://localhost:8080"
  data_dir: "/data"
  timezone: "UTC"
  log_level: "info"

database:
  url_env: "DATABASE_URL"

auth:
  session_cookie_name: "originpulse_session"
  session_ttl: "168h"
  bootstrap_token_env: "ORIGINPULSE_BOOTSTRAP_TOKEN"

pantheon:
  default_envs: ["live"]
  sftp:
    username_env: "PANTHEON_SFTP_USERNAME"
    private_key_path: "/run/secrets/pantheon_sftp_key"
    known_hosts_path: "/app/known_hosts"

sites:
  - id: "client-a"
    name: "Client A"
    pantheon_site_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    enabled: true
    envs: ["live"]
    tags: ["wordpress", "production"]

  - id: "client-b"
    name: "Client B"
    pantheon_site_id: "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
    enabled: true
    envs: ["live", "test"]
    tags: ["drupal", "high-traffic"]

collection:
  interval: "10m"
  timeout_per_site: "90s"
  max_parallel_sites: 4
  log_types:
    - "nginx-access"
    - "nginx-error"
    - "php-error"
    - "php-slow"
  raw_dir: "/data/raw"

combiner:
  combined_dir: "/data/combined"
  quarantine_dir: "/data/quarantine"
  rotation: "hourly"
  compression: "gzip"
  settling_window: "2h"
  finalize_after: "3h"

indexer:
  batch_size: 5000
  max_parallel_segments: 2

alerts:
  evaluate_every: "1m"
  default_severity: "medium"
  rules:
    traffic_spike:
      enabled: true
      min_requests_5m: 1000
      multiplier_vs_baseline: 4
    possible_ddos:
      enabled: true
      min_requests_1m: 500
      max_top_ip_share: 0.35
      max_top_asn_share: 0.60
    login_scan:
      enabled: true
      paths:
        - "/wp-login.php"
        - "/xmlrpc.php"
        - "/user/login"
        - "/admin"
      min_hits_5m: 100
    error_spike:
      enabled: true
      min_5xx_5m: 50
      multiplier_vs_baseline: 3

intel:
  refresh_every: "24h"
  dns_timeout: "2s"
  rdap_timeout: "5s"
  tor_exit_list_enabled: true
  providers:
    ahrefs:
      enabled: true
    addsearch:
      enabled: true
    googlebot:
      enabled: true
    bingbot:
      enabled: true

ollama:
  enabled: true
  base_url_env: "OLLAMA_BASE_URL"
  chat_model: "llama3.1:8b"
  timeout: "60s"
  daily_report_time: "07:00"

notifications:
  slack:
    enabled: false
    webhook_url_env: "SLACK_WEBHOOK_URL"
  email:
    enabled: false
```

## Site IDs

Use a stable local ID such as `client-a`, not the Pantheon UUID, in UI paths and internal references.

Still store the Pantheon UUID separately.

## Secret handling

Do not commit:

- Pantheon SSH private keys
- SFTP credentials
- database passwords
- session secrets
- Slack webhooks
- SMTP passwords

Use:

```text
environment variables
Docker secrets
mounted secret files
```

## Config validation

Validate at startup:

- required directories are writable
- database URL exists
- at least one site is enabled
- each site has unique local ID
- each site has Pantheon site UUID
- collection interval is valid
- combiner rotation is supported
- Ollama URL is reachable if enabled
- notification secrets exist if notification provider is enabled

## Runtime editable config

MVP can keep sites in config file.

Later, move these into the database and editable UI:

- sites
- envs
- alert thresholds
- allowlists
- blocklists
- known custom bots
- notification channels
