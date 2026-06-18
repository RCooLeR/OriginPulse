# Roadmap

## Milestone 0: Skeleton

Deliverables:

- Docker Compose boots.
- Postgres available.
- Ollama available.
- Go app builds.
- React app builds.
- Caddy/proxy serves frontend and API.
- CLI command works.

Commands:

```bash
originpulse server
originpulse worker
originpulse scheduler
originpulse migrate up
originpulse create-user
```

## Milestone 1: Auth and settings

Deliverables:

- Login page.
- Session auth.
- User management.
- Site config loaded from YAML or database.
- Basic settings page.

Acceptance:

- No dashboard route is accessible without login.
- First user can be created from CLI.
- Authenticated user can create another user.

## Milestone 2: Collector

Deliverables:

- Pantheon SFTP collection.
- Multiple sites.
- Multiple envs.
- Multiple app containers.
- Raw archive.
- Raw file manifest.
- Collector health page.

Acceptance:

- Can download logs from 20+ sites.
- One failed site does not stop the job.
- Raw files are stored safely.

## Milestone 3: Combiner

Deliverables:

- Minimal timestamp parser.
- Deduplication.
- Hourly rotated JSONL gzip combined logs.
- Combined segment manifest.
- Quarantine for bad lines.
- Rebuild command.

Acceptance:

- Re-running combiner is deterministic.
- Duplicate raw files do not duplicate output.
- Multiple containers merge correctly.
- Combined files are sorted.

## Milestone 4: Indexer and schema

Deliverables:

- Parse combined nginx access logs.
- Insert into partitioned `access_events`.
- Create rollups.
- Basic query endpoints.

Acceptance:

- Dashboard can query traffic by time/site/status.
- Top IP/path/user-agent queries work.
- Postgres can be rebuilt from combined logs.

## Milestone 5: Dashboard MVP

Deliverables:

- Overview dashboard.
- Top sites.
- Top IPs.
- Top paths.
- Top user agents.
- Top 404s.
- Top 5xx.
- Time range filters.

Acceptance:

- User can identify top traffic sources in under 30 seconds.
- User can see whether errors are rising.
- User can drill into IP detail.

## Milestone 6: Alerts

Deliverables:

- Traffic spike alert.
- Possible origin DDoS alert.
- Login/admin scan alert.
- 5xx spike alert.
- Alert detail page.
- Acknowledge/resolve.

Acceptance:

- Alert engine catches obvious spikes.
- Alerts are deduplicated.
- Alerts include evidence and recommendations.

## Milestone 7: IP intelligence

Deliverables:

- ASN/owner lookup.
- Reverse DNS.
- Known crawler classification.
- Tor exit classification.
- Manual labels/actions.
- Top ASN dashboard.

Acceptance:

- Top IPs show owner and risk.
- Known crawler user-agents are verified, not blindly trusted.
- Manual labels override automatic classification.

## Milestone 8: Ollama reports

Deliverables:

- Incident summary generation.
- Daily global report.
- Daily site report.
- Reports page.

Acceptance:

- Alerts can show a plain-English explanation.
- Daily report summarizes key traffic and issues.
- System still works when Ollama is offline.

## Milestone 9: Notifications and exports

Deliverables:

- Slack notifications.
- Email notifications.
- Blocklist export.
- Rate-limit recommendation export.
- CSV exports.

Acceptance:

- High severity alerts notify configured channel.
- User can export IP/user-agent/path lists for blocking or review.

## Milestone 10: Future integrations

Deliverables:

- Pantheon Log Forwarding ingestion mode.
- CDN/edge logs if available.
- Cloudflare/Fastly import.
- More log types.
- Long-term trend reports.
- Client-facing PDF/HTML reports.

## Possible product expansion

- Multi-tenant SaaS.
- Role-based access.
- Organization/workspace model.
- Managed hosted version.
- Agent-based deployment.
- Prometheus metrics.
- SIEM export.
