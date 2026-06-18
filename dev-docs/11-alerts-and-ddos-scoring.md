# Alerts and DDoS Scoring

## Philosophy

OriginPulse should provide early warning and recommendations.

It should not claim perfect DDoS detection. It observes origin logs and detects patterns that look abnormal or risky.

## Alert levels

```text
info
low
medium
high
critical
```

## Main alert types

```text
traffic_spike
possible_ddos
login_scan
admin_scan
xmlrpc_scan
error_spike_5xx
not_found_spike_404
single_ip_abuse
single_asn_concentration
crawler_overload
unknown_bot_spike
fake_bot_user_agent
multi_site_scan
collector_failure
indexer_lag
```

## Time buckets

Evaluate every minute using 1-minute and 5-minute windows.

Common windows:

```text
1m
5m
15m
1h
24h baseline
7d same-hour baseline
```

## Baseline approach

For MVP:

```text
current_5m compared with previous_1h_average_5m
```

Better later:

```text
current bucket compared with same hour of previous days
```

## Signals

### Traffic spike score

```text
requests_5m / baseline_requests_5m
```

### Acceleration score

```text
requests_current_1m / requests_previous_1m
```

### IP concentration score

```text
top_ip_requests / total_requests
```

### ASN concentration score

```text
top_asn_requests / total_requests
```

### Path concentration score

```text
top_path_requests / total_requests
```

### Error score

```text
5xx_rate + abnormal_5xx_growth
```

### Suspicious path score

High when traffic hits:

```text
/wp-login.php
/xmlrpc.php
/wp-admin
/user/login
/admin
/.env
/vendor
/phpmyadmin
```

### User-agent risk score

High when:

```text
empty user-agent
very old browser string
known scanner string
same user-agent across many IPs
fake known bot user-agent
high traffic unknown bot
```

## DDoS risk formula

MVP formula:

```text
ddos_risk =
  traffic_spike_score       * 0.30 +
  acceleration_score        * 0.15 +
  ip_concentration_score    * 0.15 +
  asn_concentration_score   * 0.15 +
  path_concentration_score  * 0.10 +
  error_score               * 0.10 +
  suspicious_ua_score       * 0.05
```

Normalize result to 0-100.

## Example thresholds

```yaml
possible_ddos:
  medium: 60
  high: 75
  critical: 90
```

## Important distinction

### Single-source attack

High top-IP concentration:

```text
one IP causes 60% of traffic
```

Recommendation:

```text
block/rate-limit IP
```

### Distributed attack

Low top-IP concentration but high ASN/user-agent/path concentration:

```text
1000 IPs hit same path with same user-agent
```

Recommendation:

```text
rate-limit path, challenge ASN, add WAF rule
```

### Crawler overload

Known crawler causes too much origin traffic:

```text
AhrefsBot causes 30% of origin traffic
```

Recommendation:

```text
rate-limit crawler or tune crawler settings, do not blindly block verified useful crawlers
```

## Alert deduplication

Do not create a new alert every minute.

Alert identity:

```text
rule_key + site_id + env + actor_type + actor_value + time_bucket_group
```

Example:

```text
possible_ddos + client-a + live + asn + 12345
```

Update existing alert:

```text
last_seen_at
score
details
summary
```

## Alert evidence

Each alert should store evidence:

```json
{
  "window": "5m",
  "requests": 25000,
  "baseline_requests": 3000,
  "traffic_multiplier": 8.3,
  "top_ip": "203.0.113.10",
  "top_ip_share": 0.41,
  "top_asn": 12345,
  "top_asn_org": "Example Hosting",
  "top_paths": [
    { "path": "/wp-login.php", "requests": 12000 },
    { "path": "/xmlrpc.php", "requests": 6000 }
  ],
  "status_breakdown": {
    "2xx": 500,
    "3xx": 200,
    "4xx": 23000,
    "5xx": 1300
  }
}
```

## Suggested actions

Generate actions as recommendations:

```text
block_ip
block_cidr
rate_limit_ip
rate_limit_asn
challenge_path
block_user_agent
allow_verified_bot
monitor_only
review_application_errors
check_recent_deploy
```

## Notification content

Slack/email alert example:

```text
High: Possible origin DDoS on Client A

Traffic increased 8.3x in the last 5 minutes.
Top ASN Example Hosting generated 61% of requests.
Most requested paths: /wp-login.php, /xmlrpc.php.
4xx rate: 92%, 5xx rate: 5%.

Recommended: rate-limit or challenge this ASN/path combination.
```

## False positive controls

- Do not flag verified Googlebot only because of user-agent.
- Lower severity for verified known actors unless they cause errors or huge spikes.
- Allow manual labels.
- Allow per-site thresholds.
- Ignore expected scheduled jobs when configured.
- Silence alerts for maintenance windows.

## Acceptance criteria

- Alert engine finds obvious traffic spike.
- Alert engine finds login scan.
- Alert engine finds 5xx spike.
- Alert engine groups repeated alerts.
- Alert detail includes evidence and recommendations.
- System does not auto-block traffic in MVP.
