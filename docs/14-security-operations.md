# Security and Operations

## Auth

- Login required for every app page and API route except `/healthz` and login.
- One role only: authenticated user.
- Any authenticated user can manage users.
- First user created via CLI or bootstrap token.

## Passwords

Use Argon2id.

Store:

```text
algorithm
memory
iterations
parallelism
salt
hash
```

Never store plaintext passwords.

## Sessions

Recommended:

- HttpOnly cookie
- Secure in production
- SameSite=Lax or Strict
- random token stored hashed in Postgres
- session expiration
- logout deletes session

## CSRF

If using cookie auth, add CSRF protection for state-changing requests.

## Secrets

Do not commit:

```text
Pantheon SSH keys
database password
session secret
Slack webhook
SMTP credentials
Ollama auth if added later
```

Use:

```text
Docker secrets
mounted secret files
environment variables
```

## Network exposure

Do not expose:

```text
postgres
ollama
worker
scheduler
```

Expose only:

```text
proxy/web/API through reverse proxy
```

## Data sensitivity

Access logs can contain:

- IP addresses
- user agents
- URLs
- query strings
- referrers
- session-like identifiers if apps leak them into URLs

Be careful with:

- long retention
- exports
- external sharing
- LLM prompts
- screenshots

## Retention

Suggested defaults:

```text
raw logs: 90 days
combined logs: 180 days or longer
access_events: 180 days
rollups: 2 years
alerts: 2 years
llm reports: 1 year
quarantine: 30 days
```

Make retention configurable.

## Backups

Back up:

```text
Postgres
/data/combined
config
manual labels/blocklists
```

Raw logs are useful but less critical if combined logs are trusted. For full reprocessing, back up raw logs too.

## Health checks

Endpoints:

```http
GET /api/v1/healthz
GET /api/v1/readyz
```

Check:

```text
database connection
migrations current
combined dir writable
raw dir writable
ollama reachable if enabled
scheduler heartbeat
worker heartbeat
```

## Operational dashboard

Show:

```text
last collection run
failed sites
indexer lag
open jobs
failed jobs
disk usage
latest combined segment
events indexed per minute
Ollama status
IP intel refresh status
```

## Job locking

Use database job locking with `FOR UPDATE SKIP LOCKED`.

Basic pattern:

```sql
UPDATE jobs
SET status = 'running',
    locked_at = now(),
    locked_by = $1,
    attempts = attempts + 1
WHERE id = (
  SELECT id
  FROM jobs
  WHERE status = 'pending'
    AND run_after <= now()
  ORDER BY run_after ASC
  FOR UPDATE SKIP LOCKED
  LIMIT 1
)
RETURNING *;
```

## Logs

Use structured JSON logs.

Fields:

```text
timestamp
level
service
job_id
request_id
user_id
site_id
env
message
error
duration_ms
```

## Metrics

MVP can expose `/metrics` later.

Useful metrics:

```text
collector_files_downloaded_total
collector_errors_total
combiner_segments_generated_total
combiner_lines_total
indexer_events_inserted_total
alerts_open_total
jobs_pending_total
jobs_failed_total
ollama_requests_total
```

## Disaster recovery

If Postgres is lost:

```text
1. Restore database backup if available.
2. If not, recreate schema.
3. Re-index from /data/combined.
4. Rebuild rollups.
5. Re-enrich top IPs.
6. Regenerate reports if needed.
```

If combined logs are lost:

```text
1. Restore combined logs from backup.
2. If not, rebuild from /data/raw if available.
3. If raw logs are unavailable, only remaining Postgres data can be used.
```

## Safe defaults

- Do not auto-block.
- Do not expose raw logs to public URLs.
- Do not show secrets in logs.
- Do not store session tokens in plaintext.
- Do not send raw logs to external APIs.
- Do not assume a crawler is real from user-agent alone.
