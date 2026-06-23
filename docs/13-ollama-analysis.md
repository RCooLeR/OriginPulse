# Ollama Analysis

## Purpose

Ollama provides local LLM summaries for traffic incidents and daily reports.

It should not parse raw logs.

Use deterministic code for:

- log parsing
- deduplication
- scoring
- alert creation
- IP classification

Use Ollama for:

- plain-English explanations
- likely issue category
- recommended next checks
- daily reports
- client-friendly summaries

## Architecture

```text
Postgres metrics/alerts
  |
  v
analysis bundle builder
  |
  v
Ollama chat API
  |
  v
llm_reports table
  |
  v
dashboard/report UI
```

## Report types

```text
daily_global
daily_site
incident_alert
ip_investigation
weekly_summary
```

## LLM input format

Send facts, not raw huge logs.

Example:

```json
{
  "report_type": "incident_alert",
  "range": {
    "start": "2026-06-17T14:00:00Z",
    "end": "2026-06-17T14:30:00Z"
  },
  "site": {
    "id": "client-a",
    "name": "Client A",
    "env": "live"
  },
  "scores": {
    "ddos_risk": 88,
    "traffic_spike": 92,
    "error_score": 31
  },
  "traffic": {
    "requests": 25000,
    "baseline_requests": 3000,
    "multiplier": 8.3,
    "unique_ips": 430
  },
  "top_asns": [
    {
      "asn": 12345,
      "org": "Example Hosting",
      "requests": 15250,
      "share": 0.61
    }
  ],
  "top_paths": [
    {
      "path": "/wp-login.php",
      "requests": 12000,
      "status_4xx_rate": 0.98
    }
  ],
  "status_breakdown": {
    "2xx": 500,
    "3xx": 200,
    "4xx": 23000,
    "5xx": 1300
  },
  "known_actors": [],
  "suggested_actions": [
    "rate_limit_asn",
    "challenge_path",
    "review_waf_rules"
  ]
}
```

## System prompt

```text
You are a web traffic incident analyst.
Use only the facts provided.
Do not invent IP owners, vendors, causes, or certainty.
Explain likely patterns in practical terms.
Clearly distinguish confirmed facts from hypotheses.
Prefer short actionable recommendations.
```

## User prompt template

```text
Analyze this OriginPulse incident bundle.

Return:
1. Summary
2. Likely cause
3. Evidence
4. Recommended next checks
5. Suggested mitigation
6. Confidence level

Facts:
{{json_bundle}}
```

## Output format

Ask the model to return JSON if possible:

```json
{
  "summary": "Traffic increased sharply on Client A.",
  "likely_cause": "Likely login scan or origin-layer bot flood.",
  "evidence": [
    "Requests increased 8.3x compared with baseline.",
    "61% of requests came from one ASN.",
    "Most requests hit /wp-login.php."
  ],
  "next_checks": [
    "Check CDN/WAF logs if available.",
    "Confirm whether the ASN belongs to a known crawler.",
    "Review recent deploys because 5xx rate increased."
  ],
  "mitigation": [
    "Rate-limit or challenge /wp-login.php.",
    "Consider temporary ASN-based rate limit."
  ],
  "confidence": "medium"
}
```

## Daily report

Daily input should include:

```text
total requests
top sites
sites with traffic changes
top IPs
top ASNs
top known actors
top 404s
top 5xx
open alerts
resolved alerts
collector health
recommended follow-ups
```

Daily output:

```text
Executive summary
Notable traffic changes
Errors and application issues
Bot/crawler activity
Security-looking events
Recommended actions
```

## Privacy considerations

Avoid sending full raw logs to Ollama.

Even local Ollama should receive only necessary facts because:

- reports are easier to control
- prompts are smaller
- sensitive data exposure is reduced
- deterministic evidence remains in Postgres

## Failure behavior

If Ollama is unavailable:

- keep alert active
- show deterministic alert evidence
- mark LLM report as pending/failed
- retry later
- do not block core analysis

## API integration

Ollama settings:

```yaml
ollama:
  enabled: true
  base_url: "http://ollama:11434"
  chat_model: "llama3.1:8b"
  timeout: "60s"
```

## Go client interface

```go
type Client interface {
    Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
}
```

## Acceptance criteria

- Alert detail can generate an LLM explanation.
- Daily report can be generated.
- The system works without Ollama.
- LLM output is stored with model name and input hash.
- UI clearly labels LLM analysis as generated interpretation.
