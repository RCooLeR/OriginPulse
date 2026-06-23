# Frontend Dashboard

## Stack

```text
React
TypeScript
Vite
TanStack Query
React Router
ECharts or Recharts
Tailwind or CSS modules
```

## Design goal

The dashboard should feel like a traffic/security command center, not a generic admin table.

It should answer immediately:

- Is traffic normal?
- Which site is under pressure?
- Are errors rising?
- Which IP/ASN/user-agent is causing it?
- Is this likely a crawler, attack, scanner, or app issue?
- What should we check next?

## Main routes

```text
/login
/dashboard
/sites
/sites/:siteId
/ips
/ips/:ip
/asns
/asns/:asn
/paths
/user-agents
/alerts
/alerts/:id
/reports
/settings/sites
/settings/users
/settings/alerts
/settings/intel
/system/jobs
/system/segments
```

## Dashboard cards

Top summary cards:

```text
Origin RPS
DDoS risk
Traffic spike score
5xx error rate
4xx error rate
Unique IPs
Top ASN
Top suspicious IP
Collector health
Last log sync
```

## Charts

### Traffic over time

Line chart:

```text
x: time
y: requests
series:
  all sites
  selected sites
```

### Status code over time

Stacked chart:

```text
2xx
3xx
4xx
5xx
```

### Top sites

Bar chart:

```text
site -> requests
```

### Top IPs

Table with inline bars:

```text
IP
requests
sites touched
ASN org
known actor
risk score
404 %
5xx %
last seen
```

### Top ASNs

Table:

```text
ASN
organization
requests
unique IPs
sites touched
risk score
known bots
```

### Path heatmap

Useful for attack visibility:

```text
path x time bucket -> requests
```

### User-agent breakdown

```text
known crawlers
unknown bots
browser-like
empty/malformed
suspicious
```

## Dashboard status language

Use clear labels:

```text
Normal
Elevated
Spiking
Possible scan
Possible origin DDoS
Error spike
Crawler-heavy
Unknown bot-heavy
```

Avoid claiming certainty when only logs suggest a pattern.

## IP detail page

This is a killer feature.

Sections:

```text
Header
- IP
- risk score
- ASN
- owner
- country
- reverse DNS
- known actor
- verified actor
- Tor exit
- manual label/action

Traffic summary
- requests
- RPM
- sites touched
- first seen
- last seen

Charts
- requests over time
- status codes over time

Tables
- top sites
- top paths
- top hosts
- top user agents
- recent requests sample

Recommendations
- allow
- monitor
- rate-limit
- block
- verify crawler
```

## Site detail page

Sections:

```text
Health summary
- requests
- spike score
- 4xx/5xx rates
- top IP
- top ASN
- top path
- active alerts

Charts
- traffic
- status code
- top paths
- top IPs
- user agents
- errors
```

## Alert detail page

Show:

```text
Title
Severity
Timeline
Affected sites
Involved IPs
Involved ASNs
Top paths
Top user agents
Evidence
Suggested actions
Ollama explanation
Acknowledge / Resolve buttons
```

## Reports page

Daily report:

```text
Yesterday across all sites:
- total origin requests
- top sites
- top traffic changes
- top errors
- suspicious actors
- known crawler activity
- recommendations
```

## Useful UI filters

Global filters:

```text
time range
site
environment
status code
IP
ASN
path
user-agent
known actor
risk level
```

Presets:

```text
last 15m
last 1h
last 6h
last 24h
yesterday
last 7d
custom
```

## Color/status guidelines

Use consistent severity:

```text
info
low
medium
high
critical
```

Do not rely only on color. Include labels and numbers.

## Frontend data fetching

Use TanStack Query keys like:

```ts
['dashboard', 'overview', range]
['ips', 'top', range, siteId]
['ip', ip, range]
['alerts', status]
```

## Empty states

Examples:

```text
No traffic found for this range.
No alerts are open.
No IP intelligence has been fetched yet.
Collector has not run for this site.
```

## MVP screens

Build in this order:

1. Login
2. Dashboard overview
3. Top IPs
4. IP detail
5. Top paths/errors
6. Alerts
7. Sites
8. Reports
9. Settings
