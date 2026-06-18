# OriginPulse Dev Docs

**OriginPulse** is a Dockerized multi-site Pantheon log intelligence platform.

Primary goals:

- Download logs from 20+ Pantheon sites/environments.
- Combine logs into deterministic rotated combined log files.
- Index combined logs into Postgres for analytics.
- Provide a React + TypeScript dashboard.
- Detect traffic spikes, likely origin-layer DDoS patterns, scanning, bot abuse, 4xx/5xx spikes, and suspicious IP/user-agent behavior.
- Enrich IPs with ownership, ASN, known crawler, Tor, and manual allow/block information.
- Use local Ollama models for human-readable summaries and incident explanations.

Preferred stack:

```text
Backend:   Go, chi, zerolog, urfave/cli/v2
Frontend:  React, TypeScript
Database:  Postgres
LLM:       Ollama
Runtime:   Docker Compose
Auth:      Required login, one role only
```

## Critical product rule

The combined log file is a first-class artifact.

The analysis database exists because dashboards and alerts need fast queries, but the generated combined rotated log files must be reproducible and auditable.

Recommended flow:

```text
Pantheon raw logs
  -> raw archive
  -> deterministic combiner
  -> rotated combined logs
  -> parser/indexer
  -> Postgres analytics
  -> dashboard, alerts, reports, Ollama summaries
```

## Pantheon assumptions

These docs are based on the current Pantheon log model:

- Logs can be downloaded via SFTP/rsync-style automation.
- Multiple application containers can produce multiple log directories.
- `nginx-access.log` records requests that hit nginx.
- Requests served directly by Pantheon Global CDN do not hit nginx and do not appear in `nginx-access.log`.
- Log Forwarding exists as a future integration path, but it may require private beta access.

References are collected in [15-references.md](15-references.md).

## Suggested reading order

1. [01-product-requirements.md](01-product-requirements.md)
2. [02-system-architecture.md](02-system-architecture.md)
3. [Docker Compose](../docker/README.md)
4. [04-go-service-layout.md](04-go-service-layout.md)
5. [05-config-model.md](05-config-model.md)
6. [06-collector.md](06-collector.md)
7. [07-combiner-and-rotation.md](07-combiner-and-rotation.md)
8. [08-postgres-schema.md](08-postgres-schema.md)
9. [09-api-design.md](09-api-design.md)
10. [10-frontend-dashboard.md](10-frontend-dashboard.md)
11. [11-alerts-and-ddos-scoring.md](11-alerts-and-ddos-scoring.md)
12. [12-ip-intelligence.md](12-ip-intelligence.md)
13. [13-ollama-analysis.md](13-ollama-analysis.md)
14. [14-security-operations.md](14-security-operations.md)
15. [16-roadmap.md](16-roadmap.md)
16. [17-ui-redesign-research.md](17-ui-redesign-research.md)
