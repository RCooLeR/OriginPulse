# Getting Started

This guide starts OriginPulse with Docker Compose, creates the first user, and runs the first ingest cycle.

## Requirements

- Docker Desktop or a compatible Docker Engine
- A local clone of the repository
- For Pantheon collection: an SSH private key accepted by a Pantheon user with access to the configured sites
- For local log collection: a readable directory containing log files

Postgres is included in the Compose stack. The app can run without a database only in a degraded mode; real collection and analysis require Postgres.

## Configure Docker

Create a local environment file:

```powershell
Copy-Item docker\.env.example docker\.env
```

Edit `docker\.env` and set the SSH key path if Pantheon collection is enabled:

```text
PANTHEON_SSH_KEY_FILE=C:/Users/example/.ssh/id_rsa
```

The Compose stack mounts that key into the app container as `/run/secrets/pantheon_ssh_key`.

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
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse originpulse create-user -config /app/config.yml -email admin@example.com -password "change-me"
```

Sign in through the browser with that account.

## Run The First Collection

From the UI, use the Pulse Logs or header controls to run collection and pipeline jobs.

From the CLI:

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse originpulse collect -config /app/config.yml
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse originpulse pipeline -config /app/config.yml
```

After indexing, check the Overview, Traffic, Live Logs, Security, Bots, and Pulse Logs pages.

## Health Checks

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --tail=120 originpulse
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse originpulse check-config -config /app/config.yml
```

The app health endpoint is:

```text
GET /health
GET /api/v1/healthz
```
