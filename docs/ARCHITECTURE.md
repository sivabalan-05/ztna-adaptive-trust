# Architecture

## The one-sentence version

Every request is re-evaluated from scratch against identity, device, network,
behaviour, location and time; an AI engine turns those signals into a 0–100
trust score; a policy engine turns that score, the caller's role and the
resource's sensitivity into an enforcement action; and every decision is written
to a hash-chained log that anyone can verify.

## Request path

```
                       browser
                          │  X-Device-Fingerprint (canvas/WebGL hash)
                          ▼
┌─────────────────────────────────────────────────────────────────────┐
│ CORS                                                                │
│  └─ ContextCollectorMiddleware      builds the ContextBundle        │
│      └─ RateLimitMiddleware         300/min per address             │
│          └─ route                                                   │
└─────────────────────────────────────────────────────────────────────┘
                          │
                          ▼
              get_principal  (the enforcement point for identity)
                 · decode + type-check the JWT
                 · re-read the session from the database
                 · reject if revoked, expired, idle, or MFA incomplete
                 · reject if the fingerprint differs from the token's
                          │
                          ▼
              profiling.build_signals  →  TrustSignals
                          │
                          ▼
              scoring.evaluate_factors →  weighted score + 6 factors
              overrides.apply          →  clamp, if this is *evidence*
              classifier.classify      →  LOW / MEDIUM / HIGH / CRITICAL
              decision.decide          →  baseline action
                          │
                          ▼
              PolicyEngine.evaluate    →  three gates (see below)
                          │
                          ▼
              AccessService            →  record, enforce, audit
```

## The three gates

Least privilege means an access request clears **all three**, and failing any
one is a refusal:

1. **Clearance** — the role's sensitivity ceiling must cover the resource.
   Checked first, and deliberately: no trust score lifts a role above its
   ceiling, so saying so before running the arithmetic is both cheaper and more
   honest.
2. **Policy** — the highest-priority matching policy decides (first-applicable);
   DENY outranks ALLOW within a tier. A lower-priority permissive policy never
   rescues a request a stricter one refused.
3. **Trust** — the live score must meet the resource's floor and every condition
   the matched policy attaches: MFA, known device, no VPN, country, time window.

## Layers

| Layer | Module | Responsibility |
|---|---|---|
| Gateway | `app/main.py`, `app/middleware/` | CORS, context collection, rate limiting, error shaping |
| Identity | `app/api/auth.py`, `app/services/auth_service.py` | Password, TOTP, JWT lifecycle, lockout |
| Devices | `app/services/device_service.py` | Fingerprint registry, trust-on-first-use, approval |
| Context | `app/core/context.py`, `app/external/` | GeoIP, IP reputation, VPN/Tor, notifications |
| AI | `app/ai/` | Six factors, overrides, classification, decision, XAI, anomaly, profiling |
| Policy | `app/services/policy_engine.py` | The three gates |
| Enforcement | `app/services/access_service.py` | Re-score, decide, record, enforce, audit |
| Audit | `app/services/audit_service.py` | Hash-chained append and verification |
| Live | `app/services/events.py`, `app/api/ws.py` | Event bus, WebSocket, ticket handshake |
| Workers | `app/workers/` | 30-second verification sweep, nightly retrain |

## Data model

Twelve tables. The ones that carry the design:

- **`sessions`** — the unit continuous verification re-scores. Carries the
  denormalised current score, band and action so the dashboard reads one row.
- **`trust_scores`** — every score ever computed, with its full factor
  breakdown in `factors`. This is what makes "why did it drop to 42?" answerable
  from the record rather than reconstructed.
- **`access_requests`** — every attempt, granted or not, with the exact feature
  vector that was scored. Doubles as the Isolation Forest training set;
  `is_anomalous` is the ground-truth label on seeded attack rows.
- **`audit_logs`** — hash-chained. `seq` is assigned by the service under a row
  lock rather than by a database sequence, so chain order and hash order cannot
  disagree.
- **`behavior_profiles`** — the rolling baseline. Login hours are stored as a
  circular mean, so a user who signs in at 23:00 and 01:00 gets a baseline near
  midnight rather than near noon.

## Where the verification sweep runs

The worker and the API are separate Compose services, so a score computed in one
must reach WebSocket clients attached to the other. That needs Redis pub/sub.

| `REDIS_URL` | Sweep runs in | Events travel by |
|---|---|---|
| set | the `worker` service | Redis pub/sub, relayed by the API |
| unset | the API process | in-process fan-out |

Without Redis an in-process bus cannot cross a process boundary at all, so a
sweep in the worker would publish into a bus nobody could subscribe to — it
would look like it was working and do nothing. The API logs which mode it is in
at startup. Under `APP_ENV=test` the sweep never runs in-process, because it
opens its own session from the global factory and would write to the real
database while the suite ran.

## Offline by construction

Every external service sits behind an interface with an implementation that
needs no network:

| Service | Live | Offline (default) |
|---|---|---|
| GeoIP | MaxMind GeoLite2 `.mmdb` (a local file) | Curated prefix table |
| IP reputation | AbuseIPDB, 3s timeout | Built-in blocklist + ASN heuristics |
| VPN / proxy / Tor | — | ASN tables + exit-node list |
| Notification | SMTP | Console + `system_logs` |
| MFA | — | `pyotp`, entirely local |

`GET /health` reports which implementation answered. A failed lookup degrades
the signal; it never denies the request. An external outage must not be able to
lock everyone out.
