# API Reference

The API is exposed under `/api/v1`. Most endpoints require an authenticated session cookie.

## Health And Auth

```text
GET  /health
GET  /api/v1/healthz
GET  /api/v1/auth/me
POST /api/v1/auth/login
POST /api/v1/auth/logout
```

## Dashboard And Investigation

```text
GET   /api/v1/dashboard/overview
GET   /api/v1/analysis/access-log
GET   /api/v1/investigate/traffic
GET   /api/v1/investigate/ip/{ip}
GET   /api/v1/investigate/user-agent
GET   /api/v1/investigate/security-signal
PATCH /api/v1/investigate/ip/{ip}/manual-intel
```

Investigation endpoints accept query parameters for range, site, IP, path, method, status, user agent, query parameter, probe category, and limits depending on endpoint.

## Alerts

```text
GET  /api/v1/alerts
GET  /api/v1/alerts/{id}
POST /api/v1/alerts/evaluate
```

## Reports

```text
GET  /api/v1/reports/recent
GET  /api/v1/reports/{id}
POST /api/v1/reports/generate
POST /api/v1/reports/daily/generate
```

## Notifications

```text
GET    /api/v1/notifications
POST   /api/v1/notifications/send
POST   /api/v1/notifications/test
GET    /api/v1/notifications/web-push/public-key
POST   /api/v1/notifications/web-push/subscribe
DELETE /api/v1/notifications/web-push/subscribe
```

## Sites And System

```text
GET  /api/v1/sites
GET  /api/v1/system/credentials
GET  /api/v1/system/geoip
GET  /api/v1/system/collector-health
GET  /api/v1/system/jobs
GET  /api/v1/system/job-steps
GET  /api/v1/system/retention
GET  /api/v1/system/archives
GET  /api/v1/system/archive-imports
GET  /api/v1/system/archive-coverage
GET  /api/v1/system/storage
GET  /api/v1/system/fast-read-audit
GET  /api/v1/system/collection-plan
GET  /api/v1/system/segments
POST /api/v1/system/collect
POST /api/v1/system/combine
POST /api/v1/system/index
POST /api/v1/system/pipeline
POST /api/v1/system/retention
POST /api/v1/system/archive-logs
POST /api/v1/system/import-archive
POST /api/v1/system/import-archives
POST /api/v1/system/backfill-dimensions
POST /api/v1/system/refresh-ip-intel
```

## Users

```text
GET    /api/v1/users
POST   /api/v1/users
PATCH  /api/v1/users/{id}
DELETE /api/v1/users/{id}
```

User endpoints require an authenticated session.
