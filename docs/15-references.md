# References

## Pantheon

### Automated log downloads

Pantheon docs:

```text
https://docs.pantheon.io/guides/logs-pantheon/automate-log-downloads
```

Relevant design notes:

- Pantheon documents automated log-download scripts.
- The resulting log file can be large.
- Multiple directories can be generated for sites using multiple application containers.

### Nginx access logs and GoAccess

Pantheon docs:

```text
https://docs.pantheon.io/guides/logs-pantheon/nginx-access-logs
```

Relevant design notes:

- `nginx-access.log` can be parsed for visitor IPs, user agents, frequent URLs, and 404s.
- Requests served by Pantheon Global CDN do not hit nginx and are not logged in `nginx-access.log`.

### Log Forwarding

Pantheon docs:

```text
https://docs.pantheon.io/log-forwarding
```

Relevant design notes:

- Pantheon Log Forwarding is documented as a way to stream operational logs to centralized tools.
- Current documented providers include Splunk and Sumo Logic.
- Access may require private beta approval.

## Crawler/IP intelligence references to add during implementation

Suggested provider references:

```text
Google crawler verification docs
Bing crawler verification docs
Ahrefs crawler IP ranges
AddSearch bot IP documentation
Tor bulk exit list
RDAP/RIR documentation
Team Cymru IP to ASN mapping
MaxMind GeoIP / ISP / Anonymous IP docs
```

## Internal documents

- Product requirements: [01-product-requirements.md](01-product-requirements.md)
- Architecture: [02-system-architecture.md](02-system-architecture.md)
- Combiner: [07-combiner-and-rotation.md](07-combiner-and-rotation.md)
- Alerts: [11-alerts-and-ddos-scoring.md](11-alerts-and-ddos-scoring.md)
- IP intelligence: [12-ip-intelligence.md](12-ip-intelligence.md)
