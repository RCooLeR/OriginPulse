# OriginPulse Documentation

OriginPulse collects web-origin logs, normalizes them, and turns them into a searchable operations dashboard for traffic, incidents, bots, providers, and suspicious activity.

The app is designed for teams that need to answer practical questions quickly:

- Which IPs or user agents are generating the current load?
- Is traffic coming from a verified provider, a manually trusted source, a crawler, or an attacker?
- Which paths, query parameters, and status codes are driving errors?
- Which events are recent and hot in Postgres, and which older ranges need archive import?
- Are collectors, indexers, rollups, reports, and retention healthy?

## Documentation Map

- [Getting Started](getting-started.md): install, run, sign in, and ingest first logs.
- [Architecture](architecture.md): how collection, combining, indexing, rollups, archives, and the UI fit together.
- [Configuration](configuration.md): complete configuration guide for sources, storage, retention, GeoIP, notifications, and allowlists.
- [Operations](operations.md): routine commands and dashboard workflows.
- [Traffic Analysis](traffic-analysis.md): how to use search, traffic views, query parameters, errors, and security probes.
- [IP And Bot Intelligence](ip-and-bot-intelligence.md): trusted, provider-verified, DNS-only, suspicious, and user-agent classification.
- [Storage And Retention](storage-and-retention.md): hot data, raw files, combined segments, archives, and temporary imports.
- [API Reference](api.md): HTTP endpoints exposed under `/api/v1`.
- [Security](security.md): credentials, deployment boundaries, public repository hygiene, and operational cautions.
- [Troubleshooting](troubleshooting.md): common symptoms and checks.
- [Docker](../docker/README.md): Docker Compose setup and volume notes.

## Supported Log Sources

OriginPulse supports two source types:

- `pantheon`: downloads logs over SSH/SFTP from configured Pantheon site environments.
- `local`: reads direct local log directories, including Apache-style access and error logs selected by filename masks.

Both source types feed the same pipeline after collection.

## Operating Model

```text
source logs
  -> raw downloaded files
  -> hourly combined segments
  -> indexed events and dimensions
  -> rollups, facts, alerts, reports
  -> dashboard, API, archive import
```

Raw downloaded files are short-lived intake material. Combined segments and compressed archives are the replay source. Postgres stores hot events, dimensions, rollups, facts, reports, jobs, and intelligence data for fast analysis.

## Version Control Hygiene

The public repository should contain application code, examples, docs, and redistributable assets only. Keep real `config.yml`, Docker `.env`, downloaded logs, database volumes, GeoIP runtime files, screenshots, private keys, and customer-specific identifiers out of Git.
