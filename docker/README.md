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

For host-run development against the Compose Postgres:

```powershell
$env:DATABASE_URL='postgres://originpulse:originpulse_dev_password@127.0.0.1:55432/originpulse?sslmode=disable'
```

## Persistence

- Postgres data lives in the `originpulse_postgres_data` Docker volume.
- App runtime files live in the `originpulse_originpulse_data` Docker volume at `/app/data`.
- `config.yml` is mounted read-only from the repository root.

Do not expose Postgres publicly. Back up both Docker volumes for real long-term runs.
