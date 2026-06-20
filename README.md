# OriginPulse

OriginPulse is a single-binary Go app for collecting and analyzing Pantheon origin logs.

This first slice serves:

- embedded frontend UI at `/`
- JSON API under `/api/v1/*`
- in-process background scheduler
- Pantheon collection planning based on the current SFTP/SSH log-download model

## Run locally

```bash
go run ./cmd/originpulse server -config config.example.yml
```

Open:

```text
http://localhost:8080
```

Useful API endpoints:

```text
GET  /api/v1/healthz
GET  /api/v1/dashboard/overview
GET  /api/v1/analysis/access-log
GET  /api/v1/reports/recent
POST /api/v1/reports/generate
GET  /api/v1/notifications
POST /api/v1/notifications/send
POST /api/v1/notifications/test
GET  /api/v1/notifications/web-push/public-key
POST /api/v1/notifications/web-push/subscribe
DEL  /api/v1/notifications/web-push/subscribe
GET  /api/v1/sites
GET  /api/v1/system/credentials
GET  /api/v1/system/jobs
GET  /api/v1/system/retention
GET  /api/v1/system/storage
GET  /api/v1/system/archives
GET  /api/v1/system/archive-imports
POST /api/v1/system/collect
POST /api/v1/system/pipeline
POST /api/v1/system/backfill-dimensions
```

## Pantheon credentials

For log downloads, Pantheon's published automation uses SSH/SFTP or rsync:

```text
env.site_uuid@appserver.env.site_uuid.drush.in:2222
env.site_uuid@dbserver.env.site_uuid.drush.in:2222
```

So the MVP needs:

- Pantheon site UUID
- environment name such as `live`, `test`, `dev`, or a Multidev
- an SSH private key whose public key is attached to a Pantheon user with access to those sites

A Pantheon machine token is optional for this first downloader. Add one when OriginPulse starts using Terminus/API automation to discover sites, list environments, or manage Pantheon resources.

## Commands

```bash
originpulse server -config config.yml
originpulse migrate -config config.yml
originpulse create-user -config config.yml -email admin@example.com -password "change-me"
originpulse collect -config config.yml
originpulse combine -config config.yml -log-type nginx-access -from 2026-06-17T14:00:00Z -to 2026-06-17T15:00:00Z
originpulse index -config config.yml -segment /data/combined/nginx-access/2026/06/17/14.log.gz
originpulse pipeline -config config.yml
originpulse retention -config config.yml -dry-run
originpulse storage-audit -config config.yml
originpulse web-push-keys
originpulse check-config -config config.yml
```

`DATABASE_URL` enables Postgres-backed auth, sessions, site storage, migrations, and the analytics schema. Without it, the app runs in a degraded local mode for frontend/API development.

## GeoIP / MaxMind

OriginPulse can enrich IP intelligence with GeoLite2 City. On startup it loads `GEOIP_DB_PATH` or `geoip.db_path`; if the file is missing and `MAXMIND_ACCOUNT_ID` plus `MAXMIND_LICENSE_KEY` are set, it downloads `GeoLite2-City.mmdb` and refreshes it on `geoip.update_interval`.

Downloaded `.mmdb` files are runtime data and are ignored by git.

## Notifications

SMTP credentials come from `ORIGINPULSE_SMTP_USERNAME` and `ORIGINPULSE_SMTP_PASSWORD`.
Webhook push targets can be provided as a comma-separated `ORIGINPULSE_PUSH_WEBHOOK_URLS` value.

Browser push uses VAPID keys. Generate a pair with:

```bash
originpulse web-push-keys
```

Then set `ORIGINPULSE_VAPID_PUBLIC_KEY`, `ORIGINPULSE_VAPID_PRIVATE_KEY`, and optionally `ORIGINPULSE_VAPID_SUBJECT` before starting the server. Keep the private key in the environment rather than in source-controlled config.

## Docker

Docker files live under `docker/`.

```bash
docker compose -f docker/docker-compose.yml up --build
docker compose -f docker/docker-compose.yml exec originpulse originpulse check-config -config /app/config.yml
```
