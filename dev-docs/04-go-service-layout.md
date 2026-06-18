# Go Service Layout

## Repository layout

```text
.
├── cmd/
│   └── originpulse/
│       └── main.go
├── internal/
│   ├── alerts/
│   ├── auth/
│   ├── collector/
│   ├── combiner/
│   ├── config/
│   ├── db/
│   ├── httpapi/
│   ├── indexer/
│   ├── intel/
│   ├── logs/
│   ├── ollama/
│   ├── pantheon/
│   ├── parser/
│   ├── rollups/
│   ├── scheduler/
│   └── users/
├── migrations/
├── web/
├── dev-docs/
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── config.example.yml
└── README.md
```

## CLI commands

Use `urfave/cli/v2`.

```text
originpulse server
originpulse migrate up
originpulse migrate down
originpulse create-user
originpulse collect
originpulse combine
originpulse index
originpulse rollup
originpulse analyze
originpulse enrich-ip
originpulse ollama-report
```

## Example command design

```bash
originpulse collect --site all --env live
originpulse combine --log-type nginx-access --window 2026-06-17T14:00:00Z
originpulse index --segment /data/combined/nginx-access/2026/06/17/14.log.gz
originpulse analyze --range 15m
```

## Logger

Use `zerolog`.

Standard fields:

```text
service
command
job_id
site_id
site_name
env
log_type
source_file
segment_id
duration_ms
error
```

Example:

```go
log.Info().
  Str("job_id", jobID).
  Str("site", site.Name).
  Str("env", env).
  Str("log_type", logType).
  Int("files_downloaded", n).
  Dur("duration", time.Since(start)).
  Msg("collection completed")
```

## Error strategy

Prefer typed errors for predictable states:

```text
ErrConfigInvalid
ErrSiteDisabled
ErrSFTPAuthFailed
ErrRawFileExists
ErrParseLine
ErrSegmentFinalized
ErrDatabaseUnavailable
ErrOllamaUnavailable
```

Rules:

- Collection failure for one site does not stop all sites.
- Parse failure for one line goes to quarantine.
- Failed enrichment remains pending.
- Failed Ollama summary creates a retryable job.
- Failed alert notification does not delete the alert.

## Context usage

All long-running functions must accept `context.Context`.

```go
func (c *Collector) CollectSite(ctx context.Context, site Site, env string) error
```

## Worker jobs

MVP can use database-backed jobs.

Table:

```sql
CREATE TABLE jobs (
  id uuid PRIMARY KEY,
  type text NOT NULL,
  status text NOT NULL,
  payload jsonb NOT NULL,
  attempts int NOT NULL DEFAULT 0,
  run_after timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  locked_by text,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
```

Job types:

```text
collect_site_env
combine_window
index_segment
rollup_window
evaluate_alerts
enrich_ip
refresh_known_bot_provider
generate_llm_report
send_notification
```

## HTTP server

Use `chi`.

Middleware:

```text
RequestID
RealIP
Recoverer
Logger
SecureHeaders
CSRF
AuthRequired
```

Public routes:

```text
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/healthz
```

Authenticated routes:

```text
GET /api/v1/me
GET /api/v1/dashboard/overview
GET /api/v1/sites
GET /api/v1/ips/top
GET /api/v1/ips/{ip}
GET /api/v1/alerts
GET /api/v1/reports/daily
```

## Testing strategy

Unit tests:

```text
parser
combiner dedupe
rotation segment selection
alert scoring
IP classifier
auth password hashing
```

Integration tests:

```text
Postgres migrations
indexer
API auth
dashboard queries
job locking
```

Golden file tests:

```text
input raw lines
expected combined output
expected parsed events
```
