# IP Intelligence

## Purpose

IP intelligence helps answer:

- Who owns this IP?
- Is this a known crawler?
- Is the user-agent fake?
- Is this a Tor exit?
- Is this a hosting/datacenter network?
- Has this actor touched many sites?
- Should we allow, monitor, rate-limit, or block?

## Data model

See `ip_intel` table in [08-postgres-schema.md](08-postgres-schema.md).

Core fields:

```text
ip
asn
asn_org
network
country_code
reverse_dns
forward_confirmed
known_actor
actor_type
verified_actor
is_tor_exit
is_datacenter
manual_label
manual_action
risk_score
source
refreshed_at
```

## Actor types

```text
search_bot
seo_bot
site_search_bot
llm_bot
uptime_monitor
security_scanner
tor
hosting
residential
unknown
manual
```

## Known actor examples

```text
Googlebot
Bingbot
AhrefsBot
AddSearch
OpenAI
Tor Exit
Custom Agency Monitor
```

## Important rule

Do not trust user-agent alone.

A request claiming to be `Googlebot` or `AhrefsBot` can be fake.

## Verification methods

### Reverse DNS + forward DNS

For important crawlers:

```text
1. Reverse lookup IP to hostname.
2. Check hostname suffix belongs to expected crawler.
3. Forward lookup hostname.
4. Confirm original IP is included.
```

### Published IP ranges

Some providers publish crawler ranges. Refresh them periodically and cache locally.

### Tor exit list

Fetch and cache Tor exit nodes.

### RDAP / ASN lookup

Use RDAP or an ASN lookup provider to identify owner/network.

## Enrichment workflow

```text
1. Find top/new IPs from recent access_events.
2. Check manual labels first.
3. Check known provider IP ranges.
4. Check Tor exit list.
5. Perform reverse DNS.
6. Perform forward-confirmation when applicable.
7. Resolve ASN/network owner.
8. Calculate risk score.
9. Store ip_intel row.
```

## Refresh strategy

```text
high-traffic IPs: every 6h
known actors: every 24h
low-traffic IPs: every 7d
manual labels: never overwritten
```

## Risk scoring

Example:

```text
+30 Tor exit
+25 datacenter/hosting and unknown actor
+25 high request rate
+20 high 404 ratio
+20 login/admin path hits
+15 touches many sites
+15 empty/suspicious user-agent
-40 verified known good crawler
-30 manual allow
+50 manual block
```

Clamp to 0-100.

## Manual actions

```text
allow
monitor
rate_limit
block
ignore
```

## IP detail recommendation logic

Examples:

### Verified Googlebot

```text
Action: allow or monitor
Reason: verified crawler, normal status mix
```

### AhrefsBot causing high load

```text
Action: rate-limit or tune crawler access
Reason: verified SEO crawler but high origin load
```

### Tor exit hitting login paths

```text
Action: block or challenge
Reason: Tor exit, login scan, high 404/403 ratio
```

### Unknown datacenter IP scanning many sites

```text
Action: block or rate-limit
Reason: hosting ASN, multi-site scan, suspicious paths
```

## Provider interface

Go interface idea:

```go
type Provider interface {
    Name() string
    Refresh(ctx context.Context) error
    Lookup(ctx context.Context, ip netip.Addr) (*Result, error)
}
```

Result:

```go
type Result struct {
    Actor          string
    ActorType      string
    Verified       bool
    ASN            int64
    ASNOrg         string
    Network        string
    CountryCode    string
    ReverseDNS     string
    ForwardConfirm bool
    IsTorExit      bool
    Source         map[string]any
}
```

## Caching

Use Postgres as primary cache.

Optional in-memory LRU cache for active window.

## UI ideas

Top IP table columns:

```text
IP
Requests
Sites
ASN org
Known actor
Verified
Tor
Risk
Action
```

Top ASN table columns:

```text
ASN
Organization
Requests
Unique IPs
Sites
Top paths
Risk
```

## Acceptance criteria

- IPs can be enriched on demand.
- Top traffic IPs are enriched automatically.
- Known bot user-agents are not trusted unless verified.
- Tor exits are labeled.
- Manual allow/block labels override automatic classification.
- Dashboard can group by ASN and known actor.
