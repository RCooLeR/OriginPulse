# Troubleshooting

## The App Does Not Start

Check config and container logs:

```powershell
originpulse check-config -config config.yml
docker compose --env-file docker/.env -f docker/docker-compose.yml logs --tail=120 originpulse
```

Common causes:

- invalid YAML
- missing `DATABASE_URL`
- bad SSH key path
- Postgres is not healthy
- port `8080` is already in use

## Login Fails

Create or reset a user:

```powershell
originpulse create-user -config config.yml -email admin@example.com -password "change-me"
```

When running behind HTTPS, make sure `secure_cookies` matches the deployment. A secure cookie will not work over plain HTTP.

## Collection Finds No Logs

Check:

- site is `enabled: true`
- source type is correct
- Pantheon site ID and env are correct
- SSH key is mounted and accepted
- local source path exists inside the container
- filename masks match the real files
- collection log types include the expected type

Use:

```powershell
originpulse collect -config config.yml
originpulse check-config -config config.yml
```

## Local Logs Are Mounted But Not Imported

For Docker, local paths must exist inside the container. The Compose file mounts repository `tmp/` to `/app/tmp`, so a config path like `./tmp/example.com` resolves inside the container.

Use filename masks when the directory contains unrelated logs:

```yaml
filename_masks:
  - "example-*"
```

## Advanced Search Shows No Results

Check that:

- pipeline has indexed segments
- selected range contains events
- filters are not too narrow
- IP value is exact
- status filters match the actual status family
- archive import is needed for older ranges

Run:

```powershell
originpulse pipeline -config config.yml
originpulse storage-audit -config config.yml
```

## IP Labels Look Wrong

Remember the label meanings:

- trusted: manual trust or explicit allowlist
- provider-verified: official provider source matched
- DNS-only: reverse DNS hint, not trust
- suspicious: stronger evidence such as probes, malicious user agents, Tor, or manual action

If labels are stale, refresh intelligence:

```powershell
originpulse refresh-ip-intel -config config.yml
```

## Old Data Is Missing

Hot events expire according to `retention.hot_event_max_age`. Older ranges may require archive import.

Check archive coverage in the UI or API:

```text
GET /api/v1/system/archive-coverage
```

Temporary imports expire according to `retention.temporary_import_max_age`.

## Disk Usage Is Growing

Check storage:

```powershell
originpulse storage-audit -config config.yml
originpulse retention -config config.yml -dry-run
originpulse archive-logs -config config.yml -dry-run
```

Postgres often grows faster than raw files. Raw files are capped by raw retention; archives and database tables depend on event volume and retention windows.
