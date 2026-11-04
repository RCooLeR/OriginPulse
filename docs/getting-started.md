# Getting Started

This guide starts OriginPulse with Docker Compose, creates the first user, and runs the first ingest cycle.

## Requirements

- Docker Engine 25+ with Docker Compose 2.20.2+ (or a current Docker Desktop)
- A local clone of the repository
- For Pantheon collection: an SSH private key accepted by a Pantheon user with access to the configured sites
- For local log collection: a readable directory containing log files

PostgreSQL 18 is included in the Compose stack and is the minimum supported
database version. The app can run without a database only in a degraded mode;
real collection and analysis require PostgreSQL.

## Configure Docker

Create a local environment file:

```powershell
Copy-Item docker\.env.example docker\.env
Copy-Item config.example.yml config.yml
New-Item -ItemType Directory -Force tmp | Out-Null
```

Edit `docker\.env` and set both required host-file paths:

```text
PANTHEON_SSH_KEY_FILE=C:/Users/example/.ssh/id_rsa
PANTHEON_KNOWN_HOSTS_FILE=C:/Users/example/.ssh/known_hosts
```

The Compose file mounts both files into the API and collector containers. Both
files must exist on the host before starting the stack; `known_hosts` may be
empty with the default automatic host-key updates. New and changed server keys
are accepted automatically and saved in the persistent application volume.

## Configure Sites

Copy or edit `config.yml` locally. The file is ignored by Git, so it can safely hold real site IDs and local paths on your machine.

Pantheon source example:

```yaml
sites:
  - id: "example-site"
    name: "Example Site"
    source_type: "pantheon"
    pantheon_site_id: "12345678-1234-1234-abcd-0123456789ab"
    enabled: true
    envs: ["live"]
```

Local Apache source example:

```yaml
sites:
  - id: "example-apache"
    name: "Example Apache Logs"
    source_type: "local"
    local_path: "./tmp/example.com"
    filename_masks:
      - "example-*"
    enabled: true
    envs: ["live"]
```

Use filename masks when a local log directory contains many unrelated files.

## Start The Stack

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml up --build -d
```

Open:

```text
http://localhost:8080
```

## Create The First User

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse-api originpulse create-user -config /app/config.yml -email admin@example.com -password "change-me"
```

Sign in through the browser with that account.

## Run The First Collection

From the UI, use the Pulse Logs or header controls to run collection and pipeline jobs.

From the CLI:

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse-api originpulse collect -config /app/config.yml
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse-api originpulse pipeline -config /app/config.yml
```

After indexing, check the Overview, Traffic, Live Logs, Security, Bots, and Pulse Logs pages.

## Health Checks

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --tail=120 originpulse-api originpulse-collector originpulse-ingest originpulse-reports
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse-api originpulse check-config -config /app/config.yml
```

The app health endpoint is:

```text
GET /health
GET /api/v1/healthz
```
