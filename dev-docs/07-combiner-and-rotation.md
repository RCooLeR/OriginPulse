# Combiner and Rotation

## Purpose

The combiner creates deterministic, deduplicated, sorted, rotated combined log files.

This is the core of OriginPulse.

## Core requirement

Combined log files are first-class outputs.

They must be:

- reproducible
- deduplicated
- timestamp-sorted within each segment
- rotated
- compressed
- atomically written
- indexed by manifest
- safe to rebuild

## Input

Raw downloaded files:

```text
/data/raw/{site}/{env}/{container}/{log_family}/{filename}
```

## Output

Combined rotated files:

```text
/data/combined/{log_type}/YYYY/MM/DD/HH.log.gz
```

Example:

```text
/data/combined/nginx-access/2026/06/17/14.log.gz
```

## Combined line format

Use JSON Lines for the canonical combined format.

Reason:

- keeps site/env/container metadata
- avoids losing source context
- easier to parse into Postgres
- safer than trying to preserve one nginx format across many sources

Example:

```json
{"ts":"2026-06-17T14:22:31Z","site_id":"client-a","env":"live","container_id":"appserver-1","log_type":"nginx-access","raw":"...original nginx line...","fingerprint":"..."}
```

Optional legacy export can produce nginx-style lines later.

## Minimal parsing in combiner

The combiner needs only:

```text
timestamp
raw line
source metadata
fingerprint
```

Full parsing belongs to the indexer.

## Fingerprint strategy

Fingerprint should be stable enough to prevent duplicates from overlapping downloads.

Recommended fingerprint input:

```text
site_id
env
container_id
log_type
normalized_timestamp
sha256(raw_line)
```

Do not include local path if the same remote line can appear in multiple downloaded snapshots.

Example pseudo-code:

```go
fpInput := siteID + "\x00" +
           env + "\x00" +
           containerID + "\x00" +
           logType + "\x00" +
           ts.UTC().Format(time.RFC3339Nano) + "\x00" +
           sha256Hex(rawLine)
fingerprint := sha256Hex([]byte(fpInput))
```

## Rotation

MVP rotation:

```text
hourly
```

Later:

```text
daily exports
custom rotation size
```

## Settling window

Recommended:

```text
current hour: mutable
previous hour: mutable
older than 2-3h: finalized
```

This handles late downloads.

## Segment lifecycle

```text
open
rewritten
finalized
indexed
archived
```

## Atomic write process

```text
1. Query or read all candidate raw lines for the segment.
2. Parse minimal timestamp.
3. Deduplicate by fingerprint.
4. Sort by timestamp, then fingerprint.
5. Write gzip temp file.
6. Write temp manifest.
7. fsync.
8. Rename temp file to final path.
9. Upsert combined_segments row.
```

## Segment manifest

Each segment should have a manifest in Postgres.

```sql
CREATE TABLE combined_segments (
  id uuid PRIMARY KEY,
  log_type text NOT NULL,
  bucket_start timestamptz NOT NULL,
  bucket_end timestamptz NOT NULL,
  path text NOT NULL,
  sha256 text,
  line_count bigint NOT NULL DEFAULT 0,
  min_ts timestamptz,
  max_ts timestamptz,
  status text NOT NULL,
  version int NOT NULL DEFAULT 1,
  generated_at timestamptz NOT NULL DEFAULT now(),
  indexed_at timestamptz,
  UNIQUE(log_type, bucket_start)
);
```

## Sorting

Sort by:

```text
timestamp ASC
site_id ASC
env ASC
container_id ASC
fingerprint ASC
```

This makes output deterministic.

## Quarantine

Bad lines go to:

```text
/data/quarantine/{log_type}/YYYY-MM-DD-unparsed.jsonl
```

Quarantine record:

```json
{
  "site_id": "client-a",
  "env": "live",
  "container_id": "appserver-1",
  "log_type": "nginx-access",
  "source_file": "/data/raw/...",
  "reason": "timestamp_parse_failed",
  "raw": "..."
}
```

## Rebuild command

```bash
originpulse combine --log-type nginx-access --from 2026-06-17T00:00:00Z --to 2026-06-18T00:00:00Z --force
```

## Validation command

```bash
originpulse combine validate --date 2026-06-17
```

Checks:

```text
segment exists
gzip readable
JSONL valid
line count matches manifest
sha256 matches manifest
timestamps belong to segment window
no duplicate fingerprints
```

## Acceptance criteria

- Re-running combiner produces the same segment hash if inputs did not change.
- Duplicate raw downloads do not create duplicate combined lines.
- Multiple containers are merged correctly.
- Segment files are sorted by timestamp.
- Final files are never partially written.
- Bad lines are quarantined, not lost.
