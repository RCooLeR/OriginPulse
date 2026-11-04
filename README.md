# OriginPulse

OriginPulse is a self-hosted log intelligence app for origin traffic. It collects Pantheon and local web server logs, normalizes them into searchable events, enriches IPs and user agents, and provides a dashboard for traffic, security, bot, error, retention, and archive investigations.

It is designed for operators who need to quickly answer:

- who is sending traffic
- which paths and query parameters are hot
- whether sources are trusted, provider-verified, suspicious, or unknown
- whether errors are caused by attacks, blocked probes, timeouts, or app behavior
- how much data is hot, archived, or ready for cleanup

## Documentation

Start with [docs/README.md](docs/README.md).

Key pages:

- [Getting Started](docs/getting-started.md)
- [Configuration](docs/configuration.md)
- [Operations](docs/operations.md)
- [Traffic Analysis](docs/traffic-analysis.md)
- [IP And Bot Intelligence](docs/ip-and-bot-intelligence.md)
- [Storage And Retention](docs/storage-and-retention.md)
- [API Reference](docs/api.md)
- [Security](docs/security.md)

## Run With Docker

Create a local Docker env file:

```powershell
Copy-Item docker\.env.example docker\.env
Copy-Item config.example.yml config.yml
New-Item -ItemType Directory -Force tmp | Out-Null
```

Edit `docker\.env` and set `PANTHEON_SSH_KEY_FILE` and
`PANTHEON_KNOWN_HOSTS_FILE` to existing host files. The Compose stack mounts
them into the API and collector and binds its published ports to localhost:

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml up --build -d
```

The stack automatically adds and replaces SSH host keys, storing them in its
persistent data volume. See [Docker setup](docker/README.md) to use strict host
verification instead.

Open the UI:

```text
http://localhost:8080
```

Create an initial user:

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse-api originpulse create-user -config /app/config.yml -email admin@example.com -password "change-me"
```

See [Docker setup](docker/README.md) for volume and command details.

## Run The Binary

```powershell
go run ./cmd/originpulse server -config config.example.yml
```

`DATABASE_URL` enables PostgreSQL 18+-backed auth, sessions, sites, migrations,
analytics, reports, retention, and jobs. Back up an older database and upgrade it
to PostgreSQL 18 before running the current migrations.

## Common Commands

```powershell
originpulse server -config config.yml
originpulse check-config -config config.yml
originpulse create-user -config config.yml -email admin@example.com -password "change-me"
originpulse collect -config config.yml
originpulse pipeline -config config.yml
originpulse retention -config config.yml -dry-run
originpulse archive-logs -config config.yml -dry-run
originpulse storage-audit -config config.yml
originpulse web-push-keys
```

## Supported Sources

- Pantheon logs over SSH/SFTP
- local/direct log directories, including Apache access and error logs selected by filename masks

Both source types feed the same collection, combine, index, rollup, archive, and retention pipeline.

## Public Repository Notes

Real runtime configuration and data are ignored by Git:

- `config.yml`
- `docker/.env`
- `data/`
- `tmp/`
- downloaded logs
- runtime GeoIP files
- database volumes
- private keys and credentials

Use synthetic examples in docs and tests.
