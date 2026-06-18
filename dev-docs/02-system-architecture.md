# System Architecture

## High-level architecture

```text
Pantheon SFTP
  |
  v
collector
  |
  v
raw archive
  |
  v
combiner
  |
  v
combined rotated logs
  |
  v
indexer/parser
  |
  v
Postgres
  |
  +--> alert engine
  +--> IP intelligence worker
  +--> Ollama report worker
  |
  v
Go API
  |
  v
React dashboard
```

## Runtime services

OriginPulse should run as one Go application process.

Recommended Docker Compose services:

```text
originpulse
postgres
ollama
```

The `originpulse` process serves the frontend, `/api/v1/*`, and background jobs. Postgres and Ollama remain separate dependencies because they are data/model services, not OriginPulse application processes.

## Backend responsibilities

### HTTP/API runtime

- HTTP API using `chi`.
- Embedded frontend assets.
- Auth/session management.
- User management.
- Site/environment config.
- Dashboard data.
- Investigation pages.
- Alert review.
- LLM report retrieval.
- Health checks.

### Worker runtime

- Log parsing.
- Combined file writing.
- Postgres indexing.
- Rollup generation.
- Alert evaluation.
- IP enrichment.
- Ollama report generation.

### Scheduler runtime

- Periodic collection.
- Periodic indexing.
- Periodic alert scans.
- Periodic IP intelligence refresh.
- Periodic daily report generation.

For MVP, worker and scheduler loops are in-process goroutines. If job volume later requires a split, the same package boundaries can be kept and moved behind a queue.

## Data flow

### 1. Collection

```text
configured site/env -> SFTP download -> raw_files table -> /data/raw
```

### 2. Combination

```text
raw files -> parse minimal timestamp -> dedupe -> sort -> write /data/combined
```

### 3. Indexing

```text
combined segment -> parse full fields -> access_events partition -> rollups
```

### 4. Enrichment

```text
top/new IPs -> RDAP/ASN/DNS/Tor/known bots -> ip_intel table
```

### 5. Alerting

```text
rollups + events + intel -> alert rules -> alerts table -> notifications
```

### 6. LLM summaries

```text
metrics bundle -> Ollama -> llm_reports table
```

## Why not database first?

The requirement says 100% combining to a log file. Therefore:

- Combined rotated logs are canonical outputs.
- Postgres is an analytics index.
- If Postgres is rebuilt, combined logs can re-index it.
- If parser improves, raw logs can regenerate combined logs.

## File storage

Recommended bind/volume paths:

```text
/data/raw
/data/combined
/data/quarantine
/data/exports
/data/tmp
```

Raw archive example:

```text
/data/raw/
  site-a/
    live/
      appserver-1/
        nginx/
          nginx-access.log
          nginx-access.log-2026-06-17.gz
```

Combined archive example:

```text
/data/combined/
  nginx-access/
    2026/
      06/
        17/
          14.log.gz
          15.log.gz
          16.log.gz
```

Quarantine example:

```text
/data/quarantine/
  nginx-access/
    2026-06-17-unparsed.jsonl
```

## Atomic writes

Combined segments must be written atomically:

```text
1. Build segment in memory or temp file.
2. Write to /data/tmp/segment-id.log.gz.tmp.
3. fsync file.
4. Rename into final path.
5. Update combined_segments table.
```

Never append directly to a finalized segment.

## Settling windows

A simple strategy:

```text
current hour: open
previous hour: mutable
older hours: finalized
```

This avoids missing late-downloaded lines while keeping files stable.

## Suggested Go packages

```text
router:       github.com/go-chi/chi/v5
logging:      github.com/rs/zerolog
cli:          github.com/urfave/cli/v2
postgres:     github.com/jackc/pgx/v5
migrations:   github.com/golang-migrate/migrate/v4
sessions:     signed cookies or Postgres-backed sessions
passwords:    golang.org/x/crypto/argon2
sftp:         github.com/pkg/sftp
ssh:          golang.org/x/crypto/ssh
cron:         github.com/robfig/cron/v3
```

## Internal module boundaries

```text
/internal/auth
/internal/config
/internal/db
/internal/httpapi
/internal/pantheon
/internal/collector
/internal/combiner
/internal/parser
/internal/indexer
/internal/rollups
/internal/alerts
/internal/intel
/internal/ollama
/internal/scheduler
/internal/notifications
/internal/fsutil
```

## Failure philosophy

- One broken site must not stop all collection.
- One bad log line must not stop parsing.
- One failed IP lookup must not stop analysis.
- One failed Ollama call must not stop alerting.
- All jobs must produce structured logs with job IDs.
