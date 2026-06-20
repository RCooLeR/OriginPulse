# Storage And Analysis Scenarios

## Baseline Measurements

Measured from the current local OriginPulse database:

| Metric | Value |
|---|---:|
| Access events | 2,560,820 |
| Current database size | ~7.5 GB |
| `access_events` total size, heap plus indexes | ~5.2 GB |
| Current bytes per event, heap plus indexes | ~2,046 B |
| Dimension rows | 543,965 IPs, 129,107 paths, 330,807 queries, 26,870 user agents |
| Fact rows | 29,796 security probes, 502,342 errors, 753,119 slow requests |

Observed traffic density:

| Site shape | Requests/day | IPs/day | Paths/day | UAs/day | Requests/hour | IPs/hour | Paths/hour | UAs/hour |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| example-like | ~481k | ~87k | ~27k | ~4.4k | ~25.7k | ~10.3k | ~4.2k | ~1.0k |
| secondary-site-like | ~119k | ~16k | ~8.8k | ~2.9k | ~6.4k | ~2.0k | ~1.4k | ~0.5k |

The live estimator can be reproduced with:

```powershell
$env:DATABASE_URL='postgres://originpulse:originpulse_dev_password@127.0.0.1:55432/originpulse?sslmode=disable'
go run ./cmd/originpulse storage-estimate
```

Current projection from the configured retention windows:

| Projection | Sites | Events/day | Archive-horizon requests | Active Postgres | Raw intake buffer | Compressed archives | Total with archives |
|---|---:|---:|---:|---:|---:|---:|---:|
| Current configured sites | 2 | ~922k | ~673M | ~749 GB | ~14 GB | ~188 GB | ~951 GB |
| 20-site half-secondary-site model | 20 | ~3.31M | ~2.42B | ~2.69 TB | ~52 GB | ~674 GB | ~3.41 TB |

These numbers are measured from the current short observation window of about 2.8 days, then projected through the configurable defaults: 90 days of hot events, 2 weeks of raw downloaded files, 2 years of archives/online rollup horizon, and 5 years of stored reports.

Estate model for sizing:

- 2 example-like sites
- 2 secondary-site-like sites
- 16 smaller sites
- 730 days

| Smaller-site assumption | Requests/day | 2-year events | Current raw schema | Normalized raw estimate |
|---|---:|---:|---:|---:|
| 25% of secondary-site | ~1.67M | ~1.22B | ~1.5 TB | ~0.7 TB |
| 50% of secondary-site | ~2.15M | ~1.57B | ~1.9 TB | ~0.9 TB |
| 100% of secondary-site | ~3.10M | ~2.26B | ~2.8 TB | ~1.3 TB |

The current raw schema is intentionally pessimistic for long retention because it repeats path, query, and user-agent text on every row and indexes several raw columns.

## Retention Policy Assumption

Target retention model, and current implementation status:

- Serialized reports: 5 years by default, configurable through `retention.report_max_age`.
- Dimensions for IPs, paths, queries, and user agents: retained indefinitely by default. Retention does not delete `dim_ips`, `dim_paths`, `dim_queries`, or `dim_user_agents`.
- Normalized `access_events`: 3 months by default, configurable through `retention.hot_event_max_age`.
- Raw downloaded vendor log files: 2 weeks by default, configurable through `retention.raw_file_max_age`.
- Combined daily archives: `.tar.zst` archives created for indexed combined segments older than 2 weeks, controlled by `retention.daily_archive_after`.
- Combined weekly archives: `.tar.zst` archives created from eligible daily archives or indexed segments older than 3 months, controlled by `retention.weekly_archive_after`.
- Weekly combined archives: retained for 2 years by default, configurable through `retention.archive_max_age`. Daily archives are expected to be compacted and deleted after weekly archives exist.
- Temporarily imported old data: retained for 1 week by default, configurable through `retention.temporary_import_max_age`.
- PostgreSQL facts and rollups: retained for dashboard/report horizons. Fact rows survive hot `access_events` deletion where needed for long-term reports and alerts.

This means raw downloaded files are only an intake buffer. They do not need to be sized for multi-year retention. The durable source after import is the combined archive plus Postgres dimensions, facts, rollups, and reports.

Old-data investigation flow:

1. User selects a range older than the active event-retention window.
2. UI shows a confirmation that the data is archived and needs temporary import.
3. User confirms import.
4. OriginPulse loads the relevant combined daily/weekly archives back into temporary or marked imported partitions.
5. The imported old event data is retained for 1 week by default, configurable.
6. After that window, old imported events are dropped, assuming investigations are complete.

This gives long-term replay capability without keeping multi-year raw event rows hot in Postgres.

Current verification:

- `storage-audit` reports the configured windows as:
  - raw files: `336h`
  - hot events: `2160h`
  - daily archive after: `336h`
  - weekly archive after: `2160h`
  - archive max age: `17520h`
  - report max age: `43800h`
  - temporary import max age: `168h`
- `reports-fast-read-audit -range 7d` reports:
  - `dimension_rollups_ready: true`
  - `status_rollups_ready: true`
  - `unbackfilled_full_hour_events: 0`
  - `expected_raw_range_aggregations: false`
- `archive-coverage-smoke` proves the old-data flow end to end:
  - fixture daily `.tar.zst` archives are compacted into a weekly `.tar.zst`
  - old range coverage recommends one weekly archive
  - temporary import loads archived data
  - coverage recognizes the range as already imported
  - retention deletes temporary events and the temporary import record

Remaining implementation risks:

- The live development database still has pending combined segments to index. The already indexed range is rollup-backed and fast-read ready, but the backlog must be drained before considering the local dataset complete.
- Pipeline worker concurrency greater than 1 is available through `pipeline.index_workers` and CLI/API options, with transient PostgreSQL deadlock/serialization retry and rollup repair in place. The local development config remains conservative at one worker until higher concurrency has been soak tested on production-like data.
- Temporary archive import now parses archived combined gzip members into the shared bulk dimension/event/fact insert path used by normal segment indexing. It should still be smoke-tested and benchmarked against a large old investigation range on a live PostgreSQL dataset.
- Natural daily/weekly archives have not appeared in the current live dataset because the data is newer than the configured 2-week and 3-month cutoffs. Archive behavior is currently proven by fixture smoke tests, not by naturally aged production-like data.

## Scenario Summary

| Scenario | Structure | 2-year DB size | Dashboard speed | Drilldown fidelity | Operational complexity | Verdict |
|---|---|---:|---|---|---|---|
| A. Raw events + more indexes | Current wide `access_events`, more indexes | ~1.5-2.8 TB plus extra indexes | Poor for 7d+ high-cardinality views | High | Low | Interim only |
| B. Normalized events + combined archive | Compact `access_events`, dimensions, rollups, long-lived combined segments | ~1.5-3 TB if keeping 2 years of events | Fast | High via event + segment line refs | Medium | Good full-retention model |
| C. Hot facts + archived combined segments | 3-month events, forever dimensions, long rollups/reports, temporary re-import for old data | Usually <1 TB active DB | Fast | High recent, rehydratable old archive | Medium-high | Recommended target |
| D. Rollup-first minimal events | Store rollups/facts and selected events only | Hundreds of GB plus archives | Fastest | Limited unless rehydrating archives | High | Later optimization |

Recommended path: Scenario C, built on the normalized schema from Scenario B.

## Scenario A: Current Raw Events Plus More Indexes

Structure:

- `access_events` stores timestamp, site/env/container, IP, path, query, user-agent, status, bytes, timing, fingerprint.
- Add more indexes for dashboard queries.
- Raw logs remain in files and combined segments.

Pros:

- Lowest implementation effort.
- Full fidelity remains queryable in one table.
- Easy to debug.

Cons:

- Dashboard still scans or groups raw events.
- More indexes increase write cost and storage.
- 7d/30d views get slower as data grows.
- Does not solve high-cardinality groups like IP/path/UA over long ranges.

2-year size estimate:

- Raw events: ~1.5-2.8 TB with current traffic assumptions.
- Extra indexes could push this materially higher.

Expected speed:

- 24h: acceptable with good indexes.
- 7d: unstable for high-cardinality views.
- 30d/1y: not acceptable for interactive dashboards.

Verdict:

- Not the target architecture.
- Fine only as an interim baseline.

## Scenario B: Normalized Raw Events Plus Combined Archive

Structure:

- `raw_files`: short-lived source file metadata and local paths.
- `combined_segments`: hourly normalized gz files retained long-term.
- `access_events`: compact fact table:
  - `ts`
  - `site_id`, `env`, `container_id`
  - `ip_id`
  - `path_id`
  - `query_hash` or `query_id`
  - `ua_id`
  - `status`, `bytes_sent`, timing
  - `raw_file_id`, `raw_line_no`
  - `segment_id`, `segment_line_no`
  - `fingerprint`
- Dimension tables:
  - `dim_ips`
  - `dim_paths`
  - `dim_user_agents`
  - optionally `dim_queries`
- Import-time facts:
  - `security_probe_events`
  - `error_events`
  - bot/UA classification on `dim_user_agents`
- Rollups:
  - `traffic_rollup_hour/day`
  - `ip_rollup_hour/day`
  - `path_rollup_hour/day`
  - `ua_rollup_hour/day`
  - `status_rollup_hour/day`

Pros:

- Raw event fidelity is preserved.
- Repeated long strings move out of raw rows.
- Dashboards read small rollups/fact tables.
- Drilldowns can jump to exact events and combined-segment lines.
- Raw vendor files can be deleted after 7-14 days.
- Storage remains reasonable on 10 TB NVMe NAS.

Cons:

- More schema and importer complexity.
- Need backfill/migration tooling.
- Need careful upsert and idempotency logic.

2-year size estimate:

- Normalized raw events: ~0.7-1.3 TB.
- Dimensions: likely tens to low hundreds of GB depending query retention.
- Rollups/facts: likely hundreds of GB if hourly IP/path/UA rollups are retained for 2 years.
- Total practical envelope: ~1.5-3 TB for the modeled estate.

Expected speed:

- Dashboard chips/status/timeline: milliseconds to low hundreds of milliseconds.
- Top IP/path/UA lists: milliseconds to low hundreds of milliseconds from rollups.
- Drilldown/event search: slower, but targeted by event IDs and time partitions.

Verdict:

- Recommended target.

## Scenario C: Hot Events Plus Archived Combined Segments

Structure:

- Keep raw downloaded logs for 2 weeks by default.
- Keep normalized raw events in Postgres for 3 months by default.
- Keep dimensions for IPs, paths, and user agents indefinitely by default.
- Keep reports for 5 years by default.
- Keep combined daily archives after raw files age out.
- Compact daily archives to weekly archives after 3 months.
- Keep weekly combined archives for 2 years by default.
- For older drilldown, temporarily re-import relevant combined archives.
- Drop temporarily imported old event data after 1 week by default.

Pros:

- Fast dashboards.
- Much smaller active Postgres event footprint.
- Long-term source of truth remains available through combined archives.
- Dimensions, rollups, facts, and reports remain online.
- Easier backup and maintenance.

Cons:

- Older exact request drilldowns require confirmation and temporary re-import.
- More operational logic around hot/cold retention.

2-year size estimate:

- Active DB can stay well below 1 TB depending rollup detail and report volume.
- NAS combined archives hold the long-term replay source.

Expected speed:

- Dashboards: fast.
- Recent drilldowns: fast.
- Old drilldowns: asynchronous temporary import, then normal investigation speed.

Verdict:

- Recommended target retention policy.

## Scenario D: Rollup-First, Raw Events Minimal

Structure:

- Store raw logs and combined segments.
- Store dimensions and rollups.
- Store only selected event facts:
  - errors
  - probes
  - slow requests
  - sampled successes
- Do not keep full `access_events` for 2 years.

Pros:

- Smallest DB.
- Very fast dashboard.
- Good for monitoring and reporting.

Cons:

- Less flexible investigation.
- Cannot answer arbitrary raw-event questions without reading archived logs.
- More work to ensure the right facts are captured at import time.

2-year size estimate:

- Potentially hundreds of GB rather than TB, plus raw logs on NAS.

Expected speed:

- Fastest dashboards.
- Weakest ad hoc investigation.

Verdict:

- Useful later for very long retention, not ideal as the main product model.

## Recommended Structure

Use Scenario C as the target retention policy, implemented with the normalized schema from Scenario B.

Core tables:

```sql
raw_files
combined_segments

dim_ips
dim_paths
dim_user_agents
dim_queries -- optional or hash-only first

access_events

traffic_rollup_hour
traffic_rollup_day
ip_rollup_hour
ip_rollup_day
path_rollup_hour
path_rollup_day
ua_rollup_hour
ua_rollup_day
status_rollup_hour
status_rollup_day

security_probe_events
error_events
slow_request_events
```

Raw linkage:

```text
combined_segments.id
  -> access_events.segment_id + segment_line_no

raw_files.id
  -> only needed for recent intake/debug while raw files are retained
```

This allows:

- dashboard from rollups
- details from event rows
- exact source lookup from combined segment plus line number
- reprocessing from combined segments
- short raw-file retention without losing long-term replay capability

## What To Precompute During Import

Per event:

- normalize IP/path/UA/query dimensions
- store compact event IDs
- classify UA/browser/bot/tool/OS
- classify security/admin/injection probes
- classify PHP/MySQL/WordPress indicators
- mark errors and slow requests

Per segment or time bucket:

- update traffic rollups
- update status rollups
- update IP/path/UA rollups
- update top-N materialized rows if needed

## Query Strategy

Dashboard and page cards:

- read `*_rollup_hour/day`
- no raw event scan

Lists:

- top IPs from `ip_rollup_*`
- top paths from `path_rollup_*`
- user agents/bots from `ua_rollup_*` plus `dim_user_agents`
- SQL/admin/security from `security_probe_events`
- recent errors from `error_events`

Drilldowns:

- read targeted `access_events` by IDs/time/site
- use raw file locator only when showing exact log lines

## Implementation Phases

1. Add raw line identity:
   - `access_events.raw_file_id`
   - `access_events.raw_line_no`
   - `access_events.segment_line_no`

2. Add dimensions:
   - IP, path, user-agent first
   - query hash or query dimension later

3. Move importer to batched inserts:
   - `CopyFrom` or batched upserts
   - dimension cache per segment
   - worker pool across independent segments/sites

4. Add rollup tables:
   - traffic/status first
   - IP/path/UA next

5. Move API endpoints to rollups:
   - Overview
   - Traffic
   - Live Logs lists
   - Bots
   - Errors/PHP/MySQL/Security

6. Add retention:
   - raw events partitioned by month or week
   - rollups retained for 2 years
   - raw files retained on NAS

## Final Recommendation

Do not keep adding indexes to the current raw-event table as the main solution.

Build a normalized event store linked to long-lived combined archives, with import-time rollups/facts. Keep downloaded raw files only for the short intake window, keep hot event rows for the configurable investigation window, and temporarily re-import old combined archives only when a user confirms an old-data investigation. With 10 TB NVMe NAS, this leaves plenty of space while keeping the active dashboard database fast.
