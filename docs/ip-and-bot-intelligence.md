# IP And Bot Intelligence

OriginPulse separates trust, provider verification, DNS hints, and suspicion. These labels are intentionally different because they mean different things operationally.

## IP Labels

Green means trusted. This is reserved for manual allowlist entries or sources the operator explicitly trusts.

Pink means provider-verified. The IP matched an official maintained provider list or documented provider range, such as a search crawler or AI provider. Provider-verified is not the same as trusted; it means the source is recognized.

Plain DNS means reverse DNS exists, but no trust decision follows from it. Reverse DNS can be misleading and is not enough to trust a source.

Red or orange means suspicious. Suspicion requires stronger evidence such as malicious path patterns, exploit payloads, known scanner user agents, Tor exit status, manual action, or abusive behavior.

## Official Provider Ranges

The IP intelligence worker refreshes official provider range data in the background. It also handles removals: if an IP leaves an official list, future refreshes should stop marking it provider-verified.

Provider range matching is used for recognition, not automatic trust. A cloud provider range can still host abusive traffic.

## Manual Actions

Manual allowlist entries are configured in `ip_allowlist.entries` or through the UI/API where supported.

Use manual trust for sources you control or have independently verified. Use manual suspicious/block actions when investigation evidence is strong.

## User Agent Labels

User agents are classified separately from IPs:

- Verified bot/source: strong match for known verified services.
- Official named bot: user agent claims a known crawler or service name, but IP/provider verification may still be needed.
- Known malicious: scanner, exploit tool, or clearly abusive automation.
- Generic bot/tool/browser: informational classification.

Yandex user agents are not specially verified. Treat them according to normal evidence and policy.

## Common Trusted Or Recognized Services

Provider and bot recognition can include services such as:

- Googlebot and Google services
- Bingbot and Microsoft services
- DuckDuckBot
- Applebot
- Yahoo/Verizon search crawlers
- Baidu crawlers
- Ask and AOL-style crawler identities where official data is available
- AhrefsBot
- AddSearchBot
- OpenAI and Anthropic provider ranges where official lists are available

Only use official maintained lists or documented provider sources for provider verification.

## Investigation Guidance

Do not trust:

- reverse DNS alone
- cloud ASN alone
- a famous user-agent string alone
- low error rate alone
- high error rate alone

Prefer combined evidence:

- official provider range match
- consistent user agent
- non-abusive path behavior
- expected request volume
- manual business context
- absence of exploit probes
