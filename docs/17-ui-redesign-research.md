# UI Redesign Research and Direction

## Why Redesign Now

OriginPulse is moving from a single access-log dashboard into a multi-log intelligence product. The UI should stop behaving like a collection of tables and start behaving like an investigation workspace:

- Show site health and risk at a glance.
- Make log type explicit, but do not silo evidence by log type.
- Turn every chart, signal, IP, path, user-agent, alert, report, and job into a navigable object.
- Let operators pivot from "SQL injection probe" to "source IP" to "URLs hit" to "other sites touched" without rebuilding filters manually.
- Make routine monitoring fast, and make incident investigation feel deliberate rather than improvised.

## Research Signals

The strongest patterns from mature observability and security tools:

- Grafana recommends reusable dashboards with variables and hierarchical drilldowns instead of dashboard sprawl.
  Source: https://grafana.com/docs/grafana/latest/visualizations/dashboards/build-dashboards/best-practices/
- Grafana Logs Drilldown emphasizes automatic log visualization and exploration without requiring the user to start by writing a query.
  Source: https://grafana.com/docs/grafana/latest/explore/simplified-exploration/logs/
- Elastic dashboard drilldowns let dashboard interactions open deeper Discover-style investigations with context carried forward.
  Source: https://www.elastic.co/docs/explore-analyze/dashboards/drilldowns
- Elastic Security Timeline uses an investigation workspace where alerts and fields can be added to a timeline for threat hunting.
  Source: https://www.elastic.co/docs/solutions/security/investigate/timeline
- Splunk treats drilldown as a first-class dashboard interaction that can respond to clicks on charts, rows, and table cells.
  Source: https://help.splunk.com/splunk-enterprise/create-dashboards-and-reports/simple-xml-dashboards/9.4/drilldown-and-dashboard-interactivity/use-drilldown-for-dashboard-interactivity
- Datadog Security Signals lead from a signal to "what happened" evidence, matched logs, rule details, and entity pivots.
  Source: https://docs.datadoghq.com/security/cloud_siem/triage_and_investigate/investigate_security_signals/
- OWASP frames logging and monitoring as a detection/escalation/response system, not just a storage layer.
  Source: https://owasp.org/Top10/2021/A09_2021-Security_Logging_and_Monitoring_Failures/

## Product Shape

OriginPulse should be organized around five concepts:

```text
Sites        What is affected?
Logs         What evidence exists?
Entities     Who or what is involved? IP, ASN, path, user-agent, service, actor.
Signals      What changed or looks suspicious?
Investigate  What happened, where else, and what should we do next?
```

The UI should make those concepts visible in navigation, data labels, and actions.

## Primary Navigation

Recommended top-level routes:

```text
Overview
Sites
Logs
Signals
Investigate
Reports
System
Settings
```

### Overview

Executive/operator dashboard across all selected sites and log types.

Primary job:

```text
Is anything wrong right now, and where should I click first?
```

### Sites

List of 20+ sites with health/risk status, then a site detail dashboard.

Primary job:

```text
Which site is noisy, broken, attacked, stale, or missing logs?
```

### Logs

Log-type aware explorer:

```text
Access logs
PHP/app errors
Nginx errors
PHP slow logs
Cron/job logs
Future CDN/edge logs
```

Primary job:

```text
Explore raw evidence with filters, field statistics, and saved views.
```

### Signals

Security and reliability findings:

```text
Injection probes
Admin probes
Tor traffic
Known service/crawler anomalies
5xx spikes
Slow paths
Missing or bad user-agents
Collector/indexing issues
```

Primary job:

```text
Triage ranked issues and pivot into evidence.
```

### Investigate

Entity and case-like workspace:

```text
IP detail
ASN detail
Path detail
User-agent detail
Known actor/service detail
Site+path detail
Signal detail
Investigation timeline
```

Primary job:

```text
Follow connected evidence without losing filter context.
```

### Reports

Daily/weekly/monthly/quarterly/annual generated reports, plus LLM summaries and drilldowns.

Primary job:

```text
Review a period, understand trends, and open supporting evidence.
```

### System

Collector, combiner, indexer, scheduler, retention, notifications, LLM, credentials.

Primary job:

```text
Know whether the platform itself is healthy.
```

## Dashboard Model

The dashboard should become a structured page with four bands, not a loose grid.

### 1. Situation Bar

Compact status strip, always above the fold:

```text
Overall state       Normal / Elevated / Critical
Selected scope      All sites / site / log type / range
Data freshness      latest indexed event, collector lag
Active signals      critical/high/medium counts
Traffic now         requests, change vs previous period
Reliability         5xx, slow rate, top failing site
Security            probe pressure, unknown actor pressure, Tor/service activity
```

Use labels and numbers together. Do not rely on color alone.

### 2. Prioritized Signals

This replaces "Detected issues" as a more intentional triage surface.

Rows should be grouped and ranked:

```text
Critical now
Security probes
Reliability
Traffic shape
Data pipeline
```

Each signal row should expose:

```text
severity
confidence
blast radius
affected sites
primary entity
request count
error count
first/last seen
recommended action
buttons: Open signal, Open IP, Open logs, Open report context
```

### 3. Traffic and Health

Charts should answer specific questions:

```text
Traffic timeline with previous-period overlay
Status-code timeline, not only total mix
Site heatmap: site x time bucket
Top changed sites: delta vs previous comparable period
Top failing paths
Slow paths by p95
```

### 4. Actors and Attack Surface

Make "who is doing this?" a first-class area:

```text
Top source IPs
Top ASNs
Known actors/services
Crawler verification state
User-agent classes
Tor / datacenter / unknown split
```

## Site Detail Dashboard

Site pages should be the daily working surface when the operator cares about one property.

Layout:

```text
Site header
- Site name, Pantheon UUID, envs, last collection, last indexed event
- Current status: healthy / elevated / degraded / stale
- Quick filters: env, log type, range

Site risk strip
- requests
- change vs previous period
- 4xx / 5xx / slow rate
- active signals
- top source IP
- top path
- top known actor

Tabs
- Overview
- Security
- Reliability
- Actors
- Paths
- Logs
- Reports
```

### Site Security Tab

```text
Injection probes
Admin/login probes
Sensitive file probes
Tor/datacenter sources
Unknown high-volume IPs
Known crawler claims without verification
```

Every row should include direct actions:

```text
Open signal
Open source IP
Open matching logs
Open affected path
Add manual label
```

### Site Reliability Tab

```text
5xx over time
4xx over time
Top 5xx paths
Top slow paths
Recent errors
Possible backend instability signals
```

### Site Actors Tab

```text
Source IPs
ASNs
Known services
User-agents
Bots vs browsers vs tools
Verification state
```

## Log Explorer

This is important for future log types. It should not be only a raw table.

### Log-Type Switcher

```text
Access
Nginx error
PHP error
PHP slow
Cron
Platform
CDN/edge future
```

Each log type needs:

```text
field statistics
timeline
common filters
raw rows
parsed fields
save/share filter state
open related entity
```

Access logs can show:

```text
status
method
host/path/query
client IP
ASN/actor
user-agent
bytes
request time
referrer
```

Error logs can show:

```text
severity
message fingerprint
file/function when parsed
request/path correlation when possible
site/env/container
```

## Drilldown Contract

The redesign needs a consistent interaction model.

Every clickable datum should become a structured pivot:

```json
{
  "kind": "ip | path | user_agent | signal | site | asn | actor | log_filter | report",
  "value": "...",
  "site_id": "...",
  "env": "...",
  "range": "...",
  "from": "...",
  "to": "...",
  "log_type": "nginx-access",
  "origin": "dashboard | site | report | signal"
}
```

Examples:

```text
SQL injection row -> Signal detail -> source IP detail -> URLs hit -> raw matching access logs
Tor source row -> IP detail -> all sites touched -> matching admin probes
Top 5xx path -> Path detail -> recent errors -> related PHP/nginx error logs
Known actor "Ahrefs" -> Actor detail -> IPs, paths, sites, verification state
Monthly report item -> report detail -> drilldown row -> exact-period IP/path/log explorer
```

## Entity Detail Pages

The current detail drawer is useful, but it should evolve into a reusable entity detail surface. The drawer can remain for quick lookups, while deep investigation should have routable URLs.

Recommended routes:

```text
/investigate/ip/:ip
/investigate/asn/:asn
/investigate/path?path=...
/investigate/user-agent/:hash
/investigate/actor/:actor
/signals/:id
/logs?...
```

Each entity page should have:

```text
Identity
Traffic summary
Timeline
Related signals
Related sites
Related paths
Related user-agents
Recent raw evidence
Recommended actions
Notes/manual labels
```

## Visual Design Direction

OriginPulse should feel operational, dense, and calm:

- Keep the restrained panel language, but reduce "card sprawl."
- Use section bands and split panes for major work areas.
- Use tables where comparison matters; use charts where trend or distribution matters.
- Use compact status chips for severity, confidence, actor type, and verification.
- Use fixed-height chart modules with clear labels.
- Use sticky context: current site/range/log type should always be visible.
- Prefer one strong interaction per row over many tiny buttons.
- Do not hide critical pivots behind generic "Details" text only.

## Filters and Context

Global context should become a first-class state object:

```text
range/from/to
site_id
env
log_type
status_class
actor_type
known_actor
ip/asn/path/user_agent
severity
```

The URL should carry this context so links are shareable and browser back/forward works predictably.

## Backend/API Needs

Some UI improvements can happen now, but the stronger product needs richer endpoints:

```text
GET /api/v1/overview
GET /api/v1/sites/{site_id}/overview
GET /api/v1/logs/search
GET /api/v1/logs/fields
GET /api/v1/signals
GET /api/v1/signals/{id}
GET /api/v1/entities/ip/{ip}
GET /api/v1/entities/asn/{asn}
GET /api/v1/entities/path
GET /api/v1/entities/actor/{actor}
```

The existing endpoints can be adapted first, but the UI should not keep growing around `/analysis/access-log` as the only analysis source.

## Implementation Plan

### Phase 1: Navigation and Context

- Rename main nav around Overview, Sites, Logs, Signals, Investigate, Reports, System.
- Introduce a shared `viewContext` object and URL query sync.
- Replace generic "Details" buttons with typed actions: `Open IP`, `Open logs`, `Open signal`, `Open path`.
- Keep current data endpoints.

### Phase 2: Overview Dashboard Redesign

- Replace the current dashboard grid with Situation Bar, Prioritized Signals, Traffic/Health, Actors.
- Add previous-period deltas where backend data is already available or cheap.
- Add clear links from dashboard panels to Signals, Logs, and Investigate views.

### Phase 3: Site Detail

- Create `/sites/:siteId` as a full dashboard.
- Add site tabs: Overview, Security, Reliability, Actors, Paths, Logs, Reports.
- Reuse current access-log analytics filtered by site.

### Phase 4: Signals Workspace

- Turn admin probes, injection probes, Tor sources, slow paths, and issue rows into one ranked Signals surface.
- Add signal detail views with evidence and investigation actions.

### Phase 5: Log Explorer

- Build a log-type switcher and field statistics.
- Start with access logs; add other log types behind the same UI contract.

### Phase 6: Entity Pages

- Promote the drawer logic into routable entity pages.
- Keep drawer as "quick peek"; pages become the deep investigation workspace.

### Phase 7: Reports Interlinks

- Every report chart/drilldown opens exact-period entity/log/signal context.
- Add report-to-signal and report-to-site navigation.

## Acceptance Criteria

The redesign is successful when:

- An operator can identify the top problem site in under 15 seconds.
- A SQL injection probe can be followed to IP detail and raw matching logs in two clicks.
- A top 5xx path can be followed to site, raw access rows, and correlated error logs.
- A known crawler/service can be verified or marked suspicious without reading raw tables.
- The UI works for 20+ sites without duplicating dashboards per site.
- Adding a new log type does not require inventing a new page pattern.
- Reports are not dead ends; their charts and tables open supporting evidence.

