# API Design

## Style

- JSON API.
- Cookie-based session auth.
- All routes except login/health require authentication.
- One role only.

Base path:

```text
/api/v1
```

## Public routes

```http
GET /api/v1/healthz
POST /api/v1/auth/login
POST /api/v1/auth/logout
```

## Auth routes

### Login

```http
POST /api/v1/auth/login
Content-Type: application/json
```

Request:

```json
{
  "email": "admin@example.com",
  "password": "secret"
}
```

Response:

```json
{
  "user": {
    "id": "uuid",
    "email": "admin@example.com",
    "display_name": "Admin"
  }
}
```

### Me

```http
GET /api/v1/me
```

Response:

```json
{
  "id": "uuid",
  "email": "admin@example.com",
  "display_name": "Admin"
}
```

## User management

```http
GET    /api/v1/users
POST   /api/v1/users
PATCH  /api/v1/users/{id}
DELETE /api/v1/users/{id}
```

No roles. Any authenticated user can manage users.

## Site management

```http
GET    /api/v1/sites
POST   /api/v1/sites
GET    /api/v1/sites/{site_id}
PATCH  /api/v1/sites/{site_id}
DELETE /api/v1/sites/{site_id}
```

Example site response:

```json
{
  "id": "client-a",
  "name": "Client A",
  "pantheon_site_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "enabled": true,
  "envs": ["live"],
  "tags": ["wordpress", "production"],
  "last_collection_at": "2026-06-17T14:25:00Z",
  "last_event_at": "2026-06-17T14:24:58Z"
}
```

## Dashboard

```http
GET /api/v1/dashboard/overview?range=1h
GET /api/v1/dashboard/timeseries?range=24h&interval=1m
GET /api/v1/dashboard/status-codes?range=24h
GET /api/v1/dashboard/top-sites?range=24h
GET /api/v1/dashboard/top-ips?range=24h
GET /api/v1/dashboard/top-asns?range=24h
GET /api/v1/dashboard/top-paths?range=24h
GET /api/v1/dashboard/top-user-agents?range=24h
```

Overview response:

```json
{
  "range": "1h",
  "requests": 123456,
  "requests_per_minute": 2057,
  "unique_ips": 842,
  "status_4xx_rate": 0.18,
  "status_5xx_rate": 0.02,
  "ddos_risk_score": 73,
  "traffic_spike_score": 81,
  "top_site": {
    "site_id": "client-a",
    "requests": 70211
  },
  "top_ip": {
    "ip": "203.0.113.10",
    "requests": 12003,
    "asn_org": "Example Hosting",
    "risk_score": 91
  }
}
```

## IP investigation

```http
GET /api/v1/ips/top?range=1h
GET /api/v1/ips/{ip}?range=24h
GET /api/v1/ips/{ip}/timeseries?range=24h
GET /api/v1/ips/{ip}/paths?range=24h
GET /api/v1/ips/{ip}/sites?range=24h
POST /api/v1/ips/{ip}/refresh-intel
PATCH /api/v1/ips/{ip}/manual-label
```

IP detail response:

```json
{
  "ip": "203.0.113.10",
  "intel": {
    "asn": 12345,
    "asn_org": "Example Hosting",
    "reverse_dns": "crawler.example.net",
    "known_actor": "AhrefsBot",
    "verified_actor": true,
    "is_tor_exit": false,
    "risk_score": 35
  },
  "traffic": {
    "requests": 10022,
    "sites_touched": 8,
    "status_404_rate": 0.12,
    "status_5xx_rate": 0.01,
    "first_seen": "2026-06-17T10:02:00Z",
    "last_seen": "2026-06-17T14:34:00Z"
  }
}
```

## ASN investigation

```http
GET /api/v1/asns/top?range=1h
GET /api/v1/asns/{asn}?range=24h
```

## Paths

```http
GET /api/v1/paths/top?range=24h
GET /api/v1/paths/errors?range=24h
GET /api/v1/paths/search?q=wp-login
```

## User agents

```http
GET /api/v1/user-agents/top?range=24h
GET /api/v1/user-agents/suspicious?range=24h
```

## Alerts

```http
GET   /api/v1/alerts?status=open
GET   /api/v1/alerts/{id}
POST  /api/v1/alerts/{id}/ack
POST  /api/v1/alerts/{id}/resolve
POST  /api/v1/alerts/test
```

Alert response:

```json
{
  "id": "uuid",
  "rule_key": "possible_ddos",
  "title": "Possible origin DDoS on Client A",
  "severity": "high",
  "status": "open",
  "score": 88,
  "summary": "Traffic increased 5.2x and 61% came from one ASN.",
  "details": {
    "site_id": "client-a",
    "top_asn": 12345,
    "top_paths": ["/", "/wp-login.php"],
    "recommendations": [
      "Review CDN/WAF rate limiting",
      "Check whether top ASN should be challenged"
    ]
  }
}
```

## Reports

```http
GET  /api/v1/reports/daily?date=2026-06-17
POST /api/v1/reports/daily/generate
GET  /api/v1/reports/incidents/{alert_id}
POST /api/v1/reports/incidents/{alert_id}/generate
```

## Admin/system

```http
GET  /api/v1/system/collector-health
GET  /api/v1/system/jobs
POST /api/v1/system/jobs/{id}/retry
GET  /api/v1/system/segments
POST /api/v1/system/reindex
```

## API implementation notes

- Use typed request/response structs.
- Return consistent error shape.
- Paginate large responses.
- Use server-side range limits to protect Postgres.
- Prefer precomputed rollups for dashboard endpoints.

Error shape:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "range is invalid",
    "details": {}
  }
}
```
