# Traffic Analysis

OriginPulse is built for practical origin-traffic investigations. It combines rollup views for fast scanning with targeted event detail for drilldown.

## Overview

The Overview page shows current request pressure, error rates, alert count, site health, and high-level status. Use it as the first stop during an incident.

## Traffic Page

The Traffic page answers:

- how many requests arrived in the selected range
- which status codes dominate
- which paths are hot
- which IPs and user agents are active
- which query parameters are common
- how latency is behaving

Query Parameters are intentionally shown after the main traffic sections, because they are most useful once the source IPs, paths, and status mix are understood.

## Advanced Log Search

Advanced Log Search filters indexed access events by fields such as:

- IP
- site
- path
- method
- status
- status family
- user agent
- query parameter
- time range

Use exact IP search for actor investigation. Use path and query filters when looking for a common attack target or noisy parameter.

## Status Codes

Status codes are evidence, not proof.

- 4xx can mean blocked probes, missing files, autodiscovery attempts, or normal client mistakes.
- 5xx can mean overload, upstream timeouts, application bugs, or failed attack traffic.

OriginPulse does not mark an IP suspicious based only on 4xx/5xx volume. Stronger evidence comes from path behavior, probe signatures, user agent behavior, provider data, manual actions, Tor status, and known malicious tooling.

## Security Probes

Security sections detect common patterns such as:

- WordPress and Drupal probes
- admin/login discovery
- SQL injection payloads
- XSS payloads
- sensitive file requests
- directory traversal attempts
- encoded payloads

Directory traversal requires stronger path evidence than simply seeing CMS-style URLs. Ordinary content URLs should not be classified as traversal just because they contain familiar platform path fragments.

## DDoS And Abuse Triage

During a suspected attack:

1. Check Overview for request and error spikes.
2. Open Traffic and identify top IPs, paths, user agents, and query parameters.
3. Drill into top IPs and verify whether they are trusted, provider-verified, DNS-only, suspicious, or unknown.
4. Look at path mix: repeated login, CMS, admin, API, or expensive dynamic paths matter more than raw error count alone.
5. Compare user agents with the Bots page.
6. Use manual actions only when the evidence is strong enough.

If many IPs share one path or query parameter, path-level blocking may be safer than IP blocking.
