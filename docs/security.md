# Security

OriginPulse handles operational logs, credentials, source IPs, and investigation notes. Treat it as an internal operations tool.

## Deployment Boundary

Do not expose OriginPulse directly to the public internet. Put it behind a trusted network boundary, VPN, or reverse proxy with TLS.

Use HTTPS and set:

```yaml
auth:
  secure_cookies: true
```

when serving through TLS.

## Secrets

Keep these out of Git:

- `config.yml`
- `docker/.env`
- Pantheon SSH private keys
- SMTP credentials
- VAPID private keys
- webhook URLs
- MaxMind credentials
- downloaded logs
- database dumps
- screenshots containing real customer traffic

Docker mounts the Pantheon SSH key as a secret. Prefer environment variables for credentials.

## Public Repository Hygiene

The repository should contain only:

- application code
- example configuration
- documentation
- redistributable assets
- tests with synthetic data

Do not commit real site names, real site UUIDs, customer domains, private IP intelligence notes, or proprietary icon/font assets.

## IP Blocking Caution

OriginPulse helps identify likely sources of abuse, but it should not be the only decision point for permanent blocking.

Avoid blocking based only on:

- reverse DNS
- ASN
- cloud provider identity
- 4xx count
- 5xx count
- claimed bot user agent

Prefer stronger evidence such as official provider lists, manual business context, exploit probes, suspicious paths, known malicious user agents, and repeated abusive behavior.

## Logs And Privacy

Access logs may contain IP addresses, paths, query strings, user agents, and referrers. Query strings can include sensitive tokens from upstream systems.

Review retention settings and stripping rules before long-term operation. Keep archive retention aligned with the organization’s privacy and incident-response needs.

## Updates

Keep dependencies, container images, and provider range sources current. Rebuild the app image after code or asset changes:

```powershell
docker compose --env-file docker/.env -f docker/docker-compose.yml up --build -d
```
