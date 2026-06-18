# Product Requirements

## Product name

Working name: **OriginPulse**

## One-liner

OriginPulse is a self-hosted multi-site origin log intelligence platform for Pantheon teams.

## Main users

- Developer maintaining many Pantheon sites.
- Agency support engineer.
- Technical account owner.
- DevOps engineer.
- Security-minded developer investigating traffic spikes and bots.

## Problems to solve

### 1. Logs are scattered

A team with 20+ sites has logs split by:

- site
- environment
- log type
- application container
- timestamp
- rotated file

OriginPulse must make this feel like one system.

### 2. GoAccess is useful but not enough

GoAccess is good for one log or one site, but the target use case needs:

- cross-site analysis
- shared dashboards
- historical baselines
- alerting
- IP intelligence
- bot classification
- attack scoring
- combined rotated logs
- local LLM summaries

### 3. Incident triage is slow

When traffic spikes happen, the user wants fast answers:

- Which site is affected?
- Which IPs are involved?
- Which ASN or host owns them?
- Which user agents are involved?
- Which paths are being hit?
- Are these humans, verified crawlers, fake crawlers, Tor, scanners, or unknown traffic?
- What should be blocked, challenged, allowed, or monitored?

## Non-goals for MVP

- Perfect edge/CDN traffic visibility.
- Auto-blocking traffic without human approval.
- Full SIEM replacement.
- Multi-tenant SaaS.
- Multiple roles/permissions.
- Kubernetes-only deployment.
- Parsing every possible custom log format.

## MVP goals

MVP is successful when it can:

1. Run using Docker Compose.
2. Require authentication.
3. Manage users with one role.
4. Store Pantheon site/environment config.
5. Download raw logs on a schedule.
6. Preserve raw downloaded logs.
7. Combine access logs into deterministic rotated files.
8. Index combined logs into Postgres.
9. Show a useful dashboard:
   - request volume
   - status code trends
   - top IPs
   - top ASNs
   - top hosts
   - top paths
   - top user agents
   - top 404s
   - top 5xx
   - suspicious traffic
10. Generate alerts:
   - traffic spike
   - possible origin DDoS
   - login/admin scan
   - error spike
   - bot abuse
   - unusual user-agent
11. Enrich IPs:
   - ASN
   - ASN organization
   - country
   - reverse DNS
   - known bot actor
   - Tor exit status
   - manual labels
12. Use Ollama to summarize incidents and daily reports.

## Key terms

### Origin traffic

Traffic that reaches Pantheon nginx/appserver logs.

### Edge/CDN traffic

Traffic served by CDN before nginx. This is not visible in Pantheon `nginx-access.log` unless a future CDN/log-forwarding integration is added.

### Combined segment

A deterministic, rotated file containing normalized combined log lines for a fixed time window, usually one hour.

### Event

A parsed log line stored in Postgres.

### Rollup

Aggregated metrics per minute/hour used for fast dashboard queries.

### Actor

An IP, ASN, bot, user-agent family, or host group responsible for traffic.

## Basic user stories

### Log collection

As a user, I want the system to download logs from all configured Pantheon sites so I do not need to manually fetch them.

### Combined logs

As a user, I want one combined rotated log stream so I can archive, grep, export, and audit traffic across all sites.

### Dashboard

As a user, I want a dashboard that quickly shows which sites, IPs, paths, and user agents are causing traffic.

### Attack detection

As a user, I want early warnings when traffic patterns look abnormal so I can react before the site becomes unhealthy.

### IP owner lookup

As a user, I want to see who owns traffic sources so I can distinguish known crawlers from hostile or noisy traffic.

### LLM analysis

As a user, I want a plain-English summary of likely issues and recommended next checks.

## Product principles

- Be deterministic before being smart.
- Do not trust user-agent alone.
- Preserve raw data.
- Keep combined logs reproducible.
- Prefer recommendations over automatic blocking.
- Make investigation pages excellent.
- Make everything Docker-friendly.
- Use local LLM by default for privacy.
