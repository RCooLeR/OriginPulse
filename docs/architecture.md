# Architecture

OriginPulse is a single Go service with an embedded frontend, a JSON API, background jobs, and a Postgres-backed analytics store.

## Runtime Components

- Web server: serves the dashboard and `/api/v1` endpoints.
- Scheduler: runs collection, pipeline, IP intelligence, retention, archive, report, and notification jobs.
- Collector: downloads Pantheon logs or imports local log files into the raw file registry.
- Combiner: creates hourly combined `.gz` segments from raw source logs.
- Indexer: parses combined segments, writes dimensions and events, and records facts such as errors, slow requests, and security probes.
- Rollup builder: maintains fast hourly/minute aggregate tables for dashboard queries.
- Archive service: packs older combined segments into compressed `.tar.zst` archives.
- Retention service: expires raw files, hot events, old archives, reports, and temporary archive imports according to config.
- IP intelligence service: enriches IPs with GeoIP, ASN, official provider ranges, manual actions, and request behavior.
- Report and alert services: summarize recent operational signals.

## Data Flow

```text
Pantheon SFTP or local log directory
  -> raw_files metadata and local raw files
  -> combined_segments hourly gzip files
  -> parser and indexer
  -> dim_ips, dim_paths, dim_queries, dim_user_agents
  -> access_events, error_events, slow_request_events, security_probe_events
  -> rollup tables
  -> dashboard, alerts, reports, archive import
```

The combined segment is the stable replay artifact. Postgres stores fast analytical views over that data.

## Source Types

`pantheon` sources use configured site IDs and environments to derive appserver and database server SFTP targets.

`local` sources scan a configured directory. Filename masks limit ingestion to files that belong to the configured site. The detector recognizes common access and error log names for nginx, Apache, PHP, and MySQL.

## Dashboard Shape

The frontend is served from `internal/frontend/static`. It reads the authenticated API and renders:

- Overview
- Projects / Sites
- Live Logs
- Advanced Log Search
- Traffic
- Errors
- PHP
- MySQL
- Slow Queries
- Security
- Bot / Crawler Analysis
- Reports
- Alerts
- Pulse Logs
- Settings

The UI prefers rollups and indexed facts for speed, and falls back to targeted event reads when detail is needed.

## Persistence

Docker uses two named volumes:

- `docker_pgdata`: Postgres data
- `docker_originpulse_data`: raw files, combined segments, archives, GeoIP runtime database, and app runtime files

Back up both volumes for real deployments.
