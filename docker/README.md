# Docker

This Compose stack runs the real app with Postgres and persistent OriginPulse data.

## Setup

Create a local Compose env file from the example:

```powershell
Copy-Item docker\.env.example docker\.env
```

Edit `docker\.env` and set at least:

```text
PANTHEON_SSH_KEY_FILE=C:/Users/example/.ssh/id_rsa
```

The container receives that key as `/run/secrets/pantheon_ssh_key`, which overrides the host-only Windows path in `config.yml`.

## Run

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml up --build -d
docker compose --env-file docker/.env -f docker/docker-compose.yml logs -f originpulse
```

Open:

```text
http://localhost:8080
```

## Useful Checks

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse originpulse check-config -config /app/config.yml
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse originpulse collect -config /app/config.yml
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse originpulse pipeline -config /app/config.yml -from 2026-06-20T00:00:00Z -to 2026-06-21T00:00:00Z
```

For long-run collection checks:

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml ps
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --tail=120 originpulse
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

Postgres 18 uses a different official image data layout than Postgres 16. The old PG16 `docker_pgdata` volume is not mounted by this stack anymore, so it is preserved for manual backup or dump/restore instead of being mutated in place. To migrate existing local data, export from the old PG16 stack before switching volumes, then restore into the new `originpulse-postgres` volume.

Do not expose Postgres publicly. Back up both Docker volumes for real long-term runs.
