# Docker

This Compose stack runs the real app with Postgres and persistent OriginPulse data.

## Setup

Create a local Compose env file from the example:

```powershell
Copy-Item docker\.env.example docker\.env
Copy-Item config.example.yml config.yml
New-Item -ItemType Directory -Force tmp | Out-Null
```

Set both required host-file paths to an SSH private key and a verified
`known_hosts` file:

```text
PANTHEON_SSH_KEY_FILE=C:/Users/example/.ssh/id_rsa
PANTHEON_KNOWN_HOSTS_FILE=C:/Users/example/.ssh/known_hosts
```

The single `docker/docker-compose.yml` mounts both files as Docker secrets into
the API and collector. It sets `PANTHEON_SSH_KEY_PATH` to
`/run/secrets/pantheon_ssh_key` and `PANTHEON_KNOWN_HOSTS_PATH` to
`/run/secrets/pantheon_known_hosts`, overriding host-only paths from `config.yml`.
These mounts are included whenever the services are created or recreated.

## Run

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml up --build -d
docker compose --env-file docker/.env -f docker/docker-compose.yml logs -f originpulse-api originpulse-collector originpulse-ingest originpulse-reports
```

Published API and Postgres ports bind to `127.0.0.1` by default. Set
`ORIGINPULSE_BIND_HOST` or `POSTGRES_BIND_HOST` deliberately if another host
must reach them.

Open:

```text
http://localhost:8080
```

## Useful Checks

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse-api originpulse check-config -config /app/config.yml
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse-api originpulse collect -config /app/config.yml
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse-api originpulse pipeline -config /app/config.yml -from 2026-06-20T00:00:00Z -to 2026-06-21T00:00:00Z
```

For long-run collection checks:

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --tail=120 originpulse-api originpulse-collector originpulse-ingest originpulse-reports
docker compose --env-file docker/.env -f docker/docker-compose.yml exec postgres psql -U originpulse -d originpulse -c "select count(*) filter (where rollups_1h_backfilled_at is null) as unbackfilled, max(ts) as newest_access_event, now() - max(ts) as lag from access_events;"
docker compose --env-file docker/.env -f docker/docker-compose.yml exec postgres psql -U originpulse -d originpulse -c "select type,status,started_at,finished_at,duration_ms,message,meta from job_runs order by started_at desc limit 20;"
```

For host-run development against the Compose Postgres:

```powershell
$env:DATABASE_URL='postgres://originpulse:originpulse_dev_password@127.0.0.1:55432/originpulse?sslmode=disable'
```

## Persistence

- Postgres 18 data lives in the `originpulse-postgres` Docker volume, mounted at `/var/lib/postgresql`.
- App runtime files live in the `docker_originpulse_data` Docker volume at `/app/data`.
- `config.yml` is mounted read-only from the repository root.

The volume names are explicit so existing local Docker data is reused across Compose project-name changes.

The stack pins PostgreSQL 18.6 on Debian 13 and uses PostgreSQL 18's worker
I/O method by default. Override `POSTGRES_IO_METHOD` only after benchmarking on
the deployment host. Changing `POSTGRES_PASSWORD` does not update the password
inside an existing database volume; it is an initialization setting for a new,
empty cluster.

OriginPulse migrations use PostgreSQL 18's time-ordered UUIDv7 defaults for new
records. PostgreSQL 18 is therefore the minimum supported database version.

Postgres 18 uses a different official image data layout than Postgres 16. The old PG16 `docker_pgdata` volume is not mounted by this stack anymore, so it is preserved for manual backup or dump/restore instead of being mutated in place. To migrate existing local data, export from the old PG16 stack before switching volumes, then restore into the new `originpulse-postgres` volume.

The application images use a read-only Debian 13 Distroless filesystem, run as
non-root without Linux capabilities, and keep writable state in `/app/data` and
an ephemeral `/tmp`. The builder uses Go 1.27 on Debian 13.

Do not expose Postgres publicly. Back up both Docker volumes before image or
database upgrades and for all real long-term runs.

The Compose file requires Docker Engine 25 or newer and Docker Compose 2.20.2
or newer for healthcheck `start_interval` and hardened bind-mount behavior.
