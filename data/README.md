# Optional external-data drop-ins

Everything in this directory is optional. With none of it present the platform
runs entirely on built-in tables, which is what makes an offline demo possible.
Adding a file upgrades the corresponding provider in place — no code changes.

| File | Upgrades | Where to get it |
|---|---|---|
| `GeoLite2-City.mmdb` | GeoIP: prefix table → real MaxMind database | Free MaxMind account, GeoLite2 City |
| `GeoLite2-ASN.mmdb` | Adds real ASN/ISP to the above | Same account, GeoLite2 ASN |
| `tor-exit-nodes.txt` | Tor detection: 3 built-in nodes → live list | `https://check.torproject.org/torbulkexitlist` |
| `ip-blocklist.txt` | IP reputation: built-in ranges → your own feed | Any threat feed you trust |

`GEOIP_DB_PATH` in `.env` points at the City database; the ASN database is
picked up automatically if it sits beside it.

## File formats

`tor-exit-nodes.txt` — one address per line, `#` for comments:

```
# refreshed 2026-03-01
185.220.101.4
23.129.64.130
```

`ip-blocklist.txt` — `<prefix-or-ip> <score 0-100> <comma,separated,categories>`:

```
# prefix        score  categories
203.0.113       85     brute-force,scanning
198.51.100.7    100    c2,malware
```

Prefix matching is longest-first: a full address beats a three-octet prefix,
which beats a two-octet one.

## What stays offline no matter what

GeoIP and Tor detection never make network calls — both read local files. The
only provider that can talk to the internet is IP reputation, and only when
`ABUSEIPDB_API_KEY` is set; without a key it uses `ip-blocklist.txt` plus ASN
heuristics. Even with a key, a timeout or error falls back to the local data
rather than failing the request: a reputation lookup must never be able to lock
a user out of the platform.
