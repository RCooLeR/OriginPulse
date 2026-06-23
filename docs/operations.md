# Operations

OriginPulse can be operated from the web UI, the CLI, or the JSON API.

## Common CLI Commands

```powershell
originpulse server -config config.yml
originpulse check-config -config config.yml
originpulse create-user -config config.yml -email admin@example.com -password "change-me"
originpulse collect -config config.yml
originpulse pipeline -config config.yml
originpulse retention -config config.yml -dry-run
originpulse archive-logs -config config.yml -dry-run
originpulse storage-audit -config config.yml
originpulse reports-fast-read-audit -config config.yml -range 7d
originpulse refresh-ip-intel -config config.yml
originpulse web-push-keys
```

Inside Docker, prefix commands with:

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml exec originpulse
```

## Recommended Daily Checks

Open the Pulse Logs page and check:

- recent collector jobs
- failed or skipped sites
- server cooldowns
- pending combined segments
- indexing lag
- archive and retention status
- temporary archive imports

Open the Overview and Traffic pages and check:

- current request volume
- unique IPs
- 4xx and 5xx rates
- top paths
- top query parameters
- active alerts
- suspicious sources

## Manual Ingest Flow

Run these when you want to pull and process logs immediately:

```powershell
originpulse collect -config config.yml
originpulse pipeline -config config.yml
```

The pipeline can combine and index pending segments. Use `-skip-combine` to index existing pending segments only.

## Retention And Archives

Preview cleanup:

```powershell
originpulse retention -config config.yml -dry-run
```

Create archive groups:

```powershell
originpulse archive-logs -config config.yml -dry-run
originpulse archive-logs -config config.yml -remove-archive-sources
```

`-remove-archive-sources` deletes source combined files only after a successful archive write.

## Backfill And Repair

Backfill dimensions and rollups after migration or import:

```powershell
originpulse backfill-dimensions -config config.yml -batch-size 5000 -max-batches 10
```

Use the Storage and Fast Read Audit pages to see whether rollups are ready for dashboard ranges.

## Reports And Alerts

Reports can be generated from the Reports page or CLI/API. Alerts can be evaluated manually from the Alert Center.

Notifications are sent only if the corresponding SMTP, webhook, or browser push configuration is present.

## Job History

The job tables record scheduler, collection, pipeline, archive, retention, report, alert, and notification runs. Use Pulse Logs for the UI view or `/api/v1/system/jobs` and `/api/v1/system/job-steps` for API access.
