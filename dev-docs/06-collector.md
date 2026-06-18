# Collector

## Purpose

The collector downloads logs from configured Pantheon site environments and stores them in the raw archive.

It must handle:

- many sites
- multiple environments
- multiple application containers
- retryable download failures
- overlapping downloads
- raw-file manifests
- safe partial-file handling

## Pantheon log reality

Pantheon automated log download docs note that more than one directory can be generated for sites using multiple application containers. The collector must therefore not assume one directory per site/environment.

## Inputs

```text
site_id
pantheon_site_id
env
log_types
sftp credentials
raw_dir
```

## Outputs

```text
raw files in /data/raw
raw_files database records
collector job logs
```

## Raw path format

```text
/data/raw/{site_id}/{env}/{container_id}/{log_family}/{filename}
```

Example:

```text
/data/raw/client-a/live/appserver-1/nginx/nginx-access.log
/data/raw/client-a/live/appserver-2/nginx/nginx-access.log
/data/raw/client-a/live/appserver-1/nginx/nginx-access.log-2026-06-17.gz
```

## Download strategy

For each site/env:

```text
1. Open SFTP connection.
2. List log directories.
3. Detect containers.
4. For each selected log type:
   - list files
   - compare remote metadata with raw_files table
   - download new or changed files to temp path
   - compute sha256
   - rename into raw archive
   - upsert raw_files row
5. Close connection.
```

## Remote file identity

Track:

```text
site_id
env
container_id
remote_path
remote_size
remote_mtime
local_path
sha256
first_seen_at
last_seen_at
downloaded_at
```

## Partial files

Never write directly to the final path.

```text
/data/raw/.../nginx-access.log.tmp.{job_id}
```

Then rename after successful download and checksum.

## Overlapping collection

Overlapping downloads are acceptable because deduplication happens in the combiner.

Still avoid duplicate work by checking `raw_files`.

## Logs to collect

MVP:

```text
nginx-access.log
nginx-error.log
php-error.log
```

Next:

```text
php-slow.log
php-fpm-error.log
mysqld-slow-query.log
```

## Collector command

```bash
originpulse collect --site all --env live
originpulse collect --site client-a --env live
originpulse collect --site client-a --env live --log-type nginx-access
```

## Database table

```sql
CREATE TABLE raw_files (
  id uuid PRIMARY KEY,
  site_id text NOT NULL,
  env text NOT NULL,
  container_id text NOT NULL,
  log_type text NOT NULL,
  remote_path text NOT NULL,
  remote_size bigint,
  remote_mtime timestamptz,
  local_path text NOT NULL,
  sha256 text,
  status text NOT NULL,
  error text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  downloaded_at timestamptz,
  UNIQUE(site_id, env, container_id, remote_path)
);
```

## Status values

```text
discovered
downloading
downloaded
failed
ignored
```

## Retry behavior

Retry transient errors:

```text
network timeout
SFTP disconnect
temporary auth backend failure
partial download
```

Do not retry immediately forever. Use exponential backoff and keep the next scheduler run independent.

## Observability

Every collection run should log:

```text
job_id
site_id
env
containers_found
files_seen
files_downloaded
bytes_downloaded
duration_ms
errors
```

## Acceptance criteria

- Collector downloads logs for at least 20 sites without manual steps.
- One failed site does not fail the whole run.
- Multiple appserver directories are handled.
- Raw files are preserved.
- Re-running collection does not corrupt previous files.
- Collector writes enough metadata to audit what happened.
