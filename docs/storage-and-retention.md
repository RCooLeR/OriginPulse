# Storage And Retention

OriginPulse separates hot analysis data from compressed replay archives.

## Storage Layers

Raw downloaded files are the short-lived intake buffer. They are useful for debugging collection and parser behavior.

Combined segments are hourly normalized gzip files. They are the stable replay input for indexing and archive creation.

Postgres stores hot access events, dimensions, rollups, facts, reports, alerts, jobs, and intelligence data.

Archives are compressed `.tar.zst` packages created from older combined segments. They allow old ranges to be imported temporarily when investigation requires exact historical events.

## Default Retention

The default policy is:

```yaml
retention:
  raw_file_max_age: "336h"          # 14 days
  hot_event_max_age: "1440h"        # 60 days
  daily_archive_after: "168h"       # 7 days
  weekly_archive_after: "720h"      # 30 days
  archive_max_age: "2160h"          # 90 days
  temporary_import_max_age: "168h"  # 7 days
```

Hot indexed data is kept for two months. Compressed archives are kept for three months. Daily archive groups become eligible after a week; weekly compaction becomes eligible after a month.

## Archive Import

When a selected range is older than the hot event window, the UI can recommend importing archives. Imported archive data is temporary and expires after `temporary_import_max_age`.

This keeps routine dashboard queries fast while preserving a path to older exact-event investigations.

## Retention Commands

Preview retention:

```powershell
originpulse retention -config config.yml -dry-run
```

Apply retention:

```powershell
originpulse retention -config config.yml
```

Preview archives:

```powershell
originpulse archive-logs -config config.yml -dry-run
```

Write archives and delete archived source segments:

```powershell
originpulse archive-logs -config config.yml -remove-archive-sources
```

## Capacity Planning

Postgres usually dominates storage. Raw files should stay bounded by `raw_file_max_age`. Archives grow with retained combined segments and compression ratio.

For active multi-site traffic, provision headroom for:

- Postgres table and index growth
- WAL and vacuum overhead
- rollups and facts
- archive write bursts
- attack spikes
- temporary archive imports

Use the Storage page or CLI to inspect current sizing:

```powershell
originpulse storage-audit -config config.yml
```
