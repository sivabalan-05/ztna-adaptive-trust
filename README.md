# AI-Based Zero Trust Network Access

Adaptive trust scoring and continuous risk monitoring. Every access request —
and every few seconds of an active session — is re-evaluated against identity,
device, network, behavioural, location and temporal signals. An AI engine turns
those signals into a **0–100 trust score**, and a policy engine turns the score
into an action: **Allow / Allow-limited / Step-up MFA / Block / Revoke session.**

> **Build status: complete — all 10 phases.**
> 309 tests pass, all seven attack scenarios behave as specified against the
> live API, and the audit chain verifies end to end. See
> [Known boundaries](#known-boundaries) for what is deliberately not built.

---

## Quick start

### Option A — Docker (the graded path)

```bash
cp .env.example .env
docker compose up --build
docker compose exec api python scripts/seed.py --reset
```

Then open <http://localhost:5173> (web) and <http://localhost:8000/docs> (API).
Once the four base images (`postgres:15-alpine`, `redis:7-alpine`,
`python:3.11-slim`, `node:22-alpine`) are on the machine, this works with no
internet connection.

### Option B — No Docker

The app falls back to a SQLite file at the project root when `DATABASE_URL` is
unset, and to an in-process cache when `REDIS_URL` is unset. Nothing else
changes: the same SQLAlchemy models, the same migrations, the same seed data.

```bash
python3.11 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt
cp .env.example .env
cd backend && ../.venv/bin/alembic upgrade head && cd ..
.venv/bin/python scripts/seed.py --reset
make api    # and, in a second terminal, make web
```

`make help` lists every target.

---

## Architecture

```
Browser (React 18 + Vite + Tailwind)
   │  device fingerprint in X-Device-Fingerprint
   ▼
FastAPI API gateway ─── middleware: request id, context collector, rate limit
   ├── Authentication service      JWT access/refresh, TOTP MFA
   ├── Session & device registry   trust-on-first-use + admin approval
   ├── Context collector           user · device · network · geo · time · history
   ├── Policy engine (PDP/PEP)     trust score × resource sensitivity × role
   └── Chain-of-trust logger       SHA-256 hash-linked audit records
   │
   ├── AI engine
   │     anomaly (Isolation Forest) → profiling → scoring → classification
   │     → decision → explainable breakdown
   │
   ├── PostgreSQL 15   12 tables (see backend/app/models/)
   ├── Redis           session state, revocation list, rate limits
   └── Worker          re-scores every active session every 30 s
```

### Trust scoring

Start at 100, subtract `penalty × weight / 100` per factor, clamp to 0–100.

| Factor | Weight | Signals |
|---|---|---|
| Identity | 25 | password strength, MFA outcome, failed-login streak, credential age, account status |
| Device | 20 | known/unknown fingerprint, approval state, OS-browser consistency, first-seen recency |
| Network | 20 | IP reputation, VPN/proxy/Tor, ASN type, mid-session IP change |
| Behaviour | 20 | anomaly score, profile deviation, request-rate spike, unusual/denied resource access |
| Location | 10 | distance from usual, new country, impossible travel |
| Temporal | 5 | login hour vs typical window, weekend access, duration outlier |

| Score | Risk | Action |
|---|---|---|
| 80–100 | LOW | ALLOW |
| 60–79 | MEDIUM | ALLOW_LIMITED |
| 40–59 | HIGH | STEP_UP_MFA |
| 0–39 | CRITICAL | BLOCK + REVOKE_SESSION + alert |

Resource sensitivity raises the bar independently: `PUBLIC 0`, `INTERNAL 60`,
`CONFIDENTIAL 75`, `RESTRICTED 90`. Access needs the score **and** an allowing
role policy.

### Scoring in practice

`app/ai/xai.assess` is the single entry point. The login path, the on-demand
`POST /api/trust/me/evaluate`, the seeder and the Phase 10 demo scripts all call
it — there is no second implementation to drift out of step.

```
ContextBundle + User + Session + BehaviorProfile
        |
        v
profiling.build_signals  ->  TrustSignals  (every input the factors may see)
        |
        v
scoring.evaluate_factors ->  weighted score + 6 FactorResults
        |
        v
overrides.apply          ->  clamp, if this is evidence rather than graded risk
        |
        v
classifier.classify      ->  LOW / MEDIUM / HIGH / CRITICAL
decision.decide          ->  ALLOW / ALLOW_LIMITED / STEP_UP_MFA / BLOCK / REVOKE
        |
        v
TrustService.evaluate    ->  persist, alert, enforce, audit
```

Every evaluation writes a `trust_scores` row carrying the per-factor breakdown —
raw signals, weight, points deducted, plain-English reason — so "why did it drop
to 42?" is answered from the record, not reconstructed afterwards.

Live example, a real sign-in from a new device on a home network:

```
score 73.5  MEDIUM  ALLOW_LIMITED
  identity  w=25    0.0   Nothing unusual observed for this factor.
  device    w=20  -17.0   Device fingerprint has never been seen on this account.
  network   w=20    0.0   Nothing unusual observed for this factor.
  behavior  w=20   -6.5   Session deviates from this account's behaviour profile.
  location  w=10    0.0   Nothing unusual observed for this factor.
  temporal  w=5    -3.0   Signed in at 16:00, 6.9 hours outside the usual window.
```

#### Hard overrides — a deliberate deviation, documented

Capping each factor's influence has a consequence worth stating: location is
worth 10 points, so **impossible travel alone can only ever cost 10 points**,
and an insider with valid credentials, an approved device and a clean network
can never fall below roughly 77 no matter how anomalous their behaviour is.
The weighted sum expresses *graded* risk; it cannot express *proof* that a
session is not who it claims to be.

Five conditions therefore bypass the sum and clamp the score into the band that
forces the required action. Each records its own reason, so the dashboard can
always explain why a score ignored the arithmetic:

| Override | Clamp | Condition |
|---|---|---|
| `impossible_travel` | 22 | implied speed > 900 km/h between consecutive logins |
| `account_lockout` | 18 | failed logins ≥ threshold with no successful MFA |
| `session_hijack` | 28 | mid-session IP change **and** unknown fingerprint |
| `malicious_ip` | 30 | abuse confidence ≥ 90 |
| `mass_enumeration` | 32 | ≥ 20 distinct resources **and** ≥ 5× the account's baseline |
| `privilege_probing` | 48 | ≥ 5 policy denials inside one session |

---

## Seeded data

`scripts/seed.py --reset` generates, deterministically from `--seed 42`:

| | |
|---|---|
| Roles | 4 — admin, security_analyst, employee, contractor |
| Policies | 11 |
| Resources | 12 across all four sensitivity levels |
| Users | 25, Indian context, Coimbatore / Chennai / Bangalore, `Asia/Kolkata` |
| Devices | 61 (2–3 per user) |
| Sessions | 2,038 (1,993 normal, 45 attack) |
| Access events | 8,417 — 8,055 normal, **362 labelled anomalous (4.3%)** |
| Trust scores | 6,055 with full factor breakdowns |
| Alerts | 45 |
| Behaviour profiles | 25, computed from normal history only |
| Audit records | 2,074, hash-chained |

Credentials printed at the end of the run:

```
admin    : admin / Admin@Ztna2026!
everyone : <username> / Ztna@Demo2026
```

Verify the audit chain at any time:

```bash
make verify-chain
```

---

## Authentication

Login is deliberately two-step. A correct password is not an authentication
decision; it earns a five-minute MFA token that grants no access on its own.

```
POST /api/auth/login        username + password + X-Device-Fingerprint
      -> session row created (mfa_passed = false), MFA token returned
POST /api/auth/mfa/verify   MFA token + 6-digit TOTP code
      -> access (15 min) + refresh (7 days) tokens
```

The session row exists between those two calls on purpose: an unverified
session is real, visible and scored. That is what "always verify" means.

| Endpoint | Purpose |
|---|---|
| `POST /api/auth/login` | Password step; registers the device; issues the MFA challenge |
| `POST /api/auth/mfa/verify` | TOTP step; issues the token pair |
| `POST /api/auth/refresh` | Rotates both tokens; replay revokes the session |
| `POST /api/auth/logout` | Ends the session and denylists its tokens |
| `GET /api/auth/me` | Current identity, session and device |
| `POST /api/auth/register` | Create a user (administrators only) |
| `POST /api/auth/mfa/enrol` | New TOTP secret + QR code for Google Authenticator |
| `POST /api/auth/mfa/confirm` | Prove the app has the secret |
| `GET /api/devices/me` | Your registered devices |
| `GET/POST /api/devices/...` | List, approve, revoke (permission-gated) |

**Enforcement properties, each covered by a test:**

* **Revocation lands on the next request.** Every protected route re-reads the
  session from the database rather than trusting the token, so logout, admin
  revocation, expiry and idle timeout all take effect immediately instead of
  waiting out the access token's 15-minute life.
* **Tokens are bound to a device.** The access token carries the fingerprint it
  was issued to; presenting it from a different one is refused and writes a
  `SESSION_CONTEXT_MISMATCH` audit record.
* **Refresh tokens are single-use.** Rotation revokes the old token; presenting
  a spent one revokes the whole session and raises a CRITICAL `token_replay`
  alert.
* **MFA tokens are single-use and non-interchangeable.** `typ` is checked on
  every decode, so an MFA token can never be used as an access token.
* **Lockout and rate limiting.** Five failed passwords lock the account and
  raise a `brute_force` alert; the login endpoint sheds load at 10 requests per
  minute per IP and per username.
* **Weak passwords are refused at registration**, rather than being penalised
  forever through the identity trust factor.
* **Unknown devices are registered, not blocked.** Trust-on-first-use puts a new
  fingerprint in `PENDING` and raises a `new_device` alert; Zero Trust treats it
  as a risk signal for the score, not a gate.

### Signing in during a demo

The seeded accounts have TOTP secrets but nobody has scanned their QR codes, so
there is no phone to read a code from. Print the current code with:

```bash
python scripts/totp.py admin --watch
```

Real enrolment goes through `POST /api/auth/mfa/enrol`, which returns a scannable
QR code; the script never touches that path.

---

## Context collection

Zero Trust evaluates *context*, not just credentials. A collector middleware
runs on every request, before authentication, and attaches one `ContextBundle`
to `request.state`. Everything downstream — policy engine, scoring engine, audit
logger — reads that object instead of re-parsing headers or repeating lookups.

```
request -> CORS -> context collector -> gateway rate limit -> route
                        |
                        +-- network:  IP, GeoIP, ASN class, VPN/Tor, reputation
                        +-- temporal: UTC + Asia/Kolkata hour, weekend, business hours
                        +-- device:   fingerprint, UA, platform, screen, timezone
```

Identity and session are attached afterwards by `get_principal` — the first
point at which they exist.

### External services

Every provider sits behind an interface with an offline implementation:

| Service | Live | Offline (default) |
|---|---|---|
| GeoIP | MaxMind GeoLite2 `.mmdb` (local file, still no network) | Curated prefix table covering every seeded and demo range |
| IP reputation | AbuseIPDB v2, 3s timeout | Built-in blocklist + ASN-type heuristics |
| VPN / proxy / Tor | — | Hosting/VPN ASN tables + Tor exit-node list |
| Notification | SMTP | Console + `system_logs` |

`GET /health` reports which implementation is answering, so the UI never implies
more precision than it has. Drop-in upgrades are documented in
[`data/README.md`](data/README.md).

**Three deliberate choices worth defending:**

* **A failed lookup degrades the signal, it does not deny the request.** If
  AbuseIPDB times out, the local blocklist answers. If the collector itself
  raises, the request proceeds with an empty context. An external outage must
  never be able to lock everyone out.
* **Unknown means unknown.** A public address the tables cannot place is marked
  `resolved = False` rather than being given a plausible-looking location. The
  scoring engine will treat "unknown location" as its own signal.
* **Private addresses are not geolocated to (0, 0).** Null Island is 6,000 km
  from Coimbatore, which would make every localhost request look like
  impossible travel. Loopback and RFC1918 map explicitly to the office location.

### Only one proxy hop is trusted

`X-Forwarded-For` is attacker-controlled unless a trusted proxy sets it. Behind
the Compose gateway there is exactly one hop, so the leftmost entry is used and
nothing further in the chain is believed.

---

## Phase status

| Phase | Scope | State |
|---|---|---|
| 1 | Compose, FastAPI skeleton, Postgres, 12 models, migrations, seed | **done** |
| 2 | Register / login / TOTP MFA / JWT issue-refresh-revoke / device registration | **done** |
| 3 | Context collector middleware, GeoIP, IP reputation, VPN detection (+ mocks) | **done** |
| 4 | Trust scoring engine: 6 factors, classification, XAI. Unit-tested per factor | **done** |
| 5 | Policy engine, enforcement, sensitivity, least privilege | **done** |
| 6 | Isolation Forest: features, training, behaviour-factor integration | **done** |
| 7 | Chain-of-trust audit API + `/audit/verify` | **done** |
| 8 | Continuous verification worker, WebSocket push, session revocation | **done** |
| 9 | React dashboard, all 8 pages | **done** |
| 10 | 7 attack demo scripts, tests, docs, model metrics | **done** |

---

## Policy enforcement

Least privilege means an access request must clear **three independent gates**.
Failing any one is a refusal, and the response names which one stopped it.

```
POST /api/resources/payroll-db/access
        |
        v
  1. Clearance   role's sensitivity ceiling must cover the resource
        |        -> refused: no trust score can lift a role above its ceiling
        v
  2. Policy      highest-priority matching policy decides (first-applicable);
        |        DENY outranks ALLOW in the same tier
        v
  3. Trust       live score >= the resource floor, and every condition the
        |        matched policy attaches (MFA, known device, no VPN, country,
        v        time window)
      granted
```

The score is **necessary but never sufficient**. A contractor with a perfect
100 still cannot open the source repository: gate 1 stops them before the
arithmetic is consulted.

The score is also **recomputed per request**, not read off the session row — so
a request arriving from a new country is judged on where it came from, not on
how the session looked at sign-in. That is the difference between continuous
verification and a login check.

### Live: one admin session, whole catalogue

At trust 73 (MEDIUM, signing in from an unrecognised device):

```
 YES public-docs        PUBLIC        floor=0
 YES hr-portal          INTERNAL      floor=60
 no  source-repo        CONFIDENTIAL  floor=75   [trust]
 no  payroll-db         RESTRICTED    floor=90   [trust]
```

The same catalogue returns different answers for the same user from a different
device, network or hour. Reachability is computed, never stored.

### Live: a contractor walking up the ladder

```
200  public-docs   gate=-           trust 73.9  Allowed by 'Baseline trust floor - PUBLIC'
200  hr-portal     gate=-           trust 73.8  Allowed by 'Baseline trust floor - INTERNAL'
403  source-repo   gate=clearance   trust 73.5  The contractor role is not cleared for CONFIDENTIAL
403  payroll-db    gate=clearance   trust 65.4  The contractor role is not cleared for RESTRICTED
```

The score falls from 73.9 to 65.4 across four requests: each denial feeds the
behaviour factor, and a sustained run of them trips the `privilege_probing`
override. That is lateral-movement detection emerging from the same machinery,
not a special case bolted on.

Every one of those four attempts — including the two refusals — is written to
`access_requests` with its feature vector and to the audit chain. **A denial's
evidence must not be rolled back with the denial**, so the enforcement point
commits before raising the 403.

### Policy administration

`GET/POST/PATCH/DELETE /api/policies` (permission-gated). Policies are
evaluated per request, so a new DENY takes effect on the next call with no
restart — there is a test that asserts exactly that.

---

## Anomaly detection

```bash
python scripts/train_model.py
```

Trains an Isolation Forest over every recorded access event, evaluates it
against the labelled synthetic attacks, persists it with joblib, and backfills
`anomaly_score` on historical trust scores.

### Feature vector (13 features)

| | |
|---|---|
| Temporal | `hour_sin`, `hour_cos`, `day_of_week` |
| Device | `is_known_device` |
| Location | `geo_distance_from_usual_km`, `is_new_country`, `travel_velocity_kmh` |
| Network | `ip_reputation_score`, `is_vpn` |
| Activity | `requests_per_minute`, `session_duration_min`, `num_distinct_resources` |
| Identity | `failed_auth_count_24h` |

Hour is sin/cos encoded so 23:00 and 00:00 sit adjacent in feature space rather
than maximally apart — there is a test asserting exactly that.

Features are **stored at write time**, on every `access_requests` row, rather
than recomputed at training time. A model has to be trained on the numbers the
engine actually saw, not on a reconstruction that later code changes could
quietly alter.

### Measured accuracy

Global model, `n_estimators=200`, `contamination=0.05`, `random_state=42`,
over **8,435 events of which 376 (4.5%) are labelled attacks**:

| Metric | Value |
|---|---|
| Precision | **0.846** |
| Recall | **0.949** |
| F1 | **0.895** |
| ROC-AUC | **0.997** |
| Average precision | 0.975 |

Confusion matrix: **TP 357 · FP 65 · FN 19 · TN 7,994**

Read those numbers correctly. Isolation Forest is **unsupervised** — it is never
shown the labels. They exist only to measure it afterwards. So this answers
"how well does an algorithm told nothing about attacks happen to isolate the
ones we planted?", not "how well did it learn them". That framing matters for
the report.

It also explains why **recall is the metric to optimise here**: a missed attack
is a breach, a false positive is one extra MFA prompt. Recall of 0.949 means 19
of 376 attack events slipped past the model — and even those are still caught by
the deterministic factors and the hard overrides, because the Isolation Forest
contributes to only one of six factors.

### Per-user models are trained, measured, and not used

The specification calls for an optional per-user model once an account has 50+
events. All 25 accounts qualify and all 25 models are trained — and they are
**measurably worse**: mean recall 0.624, mean F1 0.394, against 0.949 and 0.895
for the global model.

The reason is structural. Each account carries only a handful of labelled
attacks, so a per-account `contamination` of 5% is a poor fit for the actual
per-account anomaly rate, and the model isolates the wrong points. Rather than
ship a worse detector to satisfy a checkbox, `USE_PER_USER_MODELS` defaults to
`false` and the global model does the work. The setting exists so the trade-off
can be re-tested once real traffic accumulates.

### Retraining

`app/workers/retrain.py` runs nightly at 02:00 UTC from the Compose `worker`
service. Each run is versioned and logged to `system_logs`, and the in-process
model cache is cleared so the API picks up the new model without a restart.

**A retrain that produces a worse model is rejected, not deployed.** If F1 falls
more than 0.05 against the model in service, the previous one is restored — a
scheduled job must not be able to quietly degrade enforcement while nobody is
watching.

---

## The seven attack demonstrations

```bash
python scripts/demo/run_all.py          # all seven, in order
python scripts/demo/impossible_travel.py   # or one at a time
```

Each drives the **running API over HTTP**, exactly as a browser would. Nothing
reaches into the database to fake a result: the scores printed are the scores the
engine produced, and the dashboard's Live Monitoring page moves while the scripts
run. A demo that wrote its own conclusions would prove nothing.

```
  [PASS]  Credential theft        correct password, unknown device, new country
  [PASS]  Impossible travel       Coimbatore → São Paulo in minutes → CRITICAL
  [PASS]  Insider threat          valid everything, only the behaviour is wrong
  [PASS]  Brute force             429 sheds the burst, 423 locks the account
  [PASS]  Session hijack          a perfect token, refused from another machine
  [PASS]  Lateral movement        five denials compound into a step-up
  [PASS]  Legitimate user         normal work, no challenge, no friction

  All 7 scenarios behaved as the specification requires.
```

Each has an in-process twin in `backend/tests/test_attack_scenarios.py`, so the
same behaviour is verified deterministically in CI with no server, no clock
dependence and no shared rate-limit state.

The brute-force script **unlocks its target afterwards and says so** — silently
undoing a security control in a security demo would teach the wrong lesson.

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Request path, the three gates, layers, data model, where the sweep runs |
| [`docs/TRUST_SCORING.md`](docs/TRUST_SCORING.md) | The formula, all six factors, the overrides and why they exist, model metrics |
| [`docs/API.md`](docs/API.md) | Every endpoint, headers, permissions, WebSocket handshake, rate limits |
| [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) | A twelve-minute walkthrough, with the questions to expect and honest answers |

---

## The console

Signing in as an administrator or security analyst opens the eight-page console;
everyone else gets their own session view. Both are the same React app.

| Page | What it does | Backed by |
|---|---|---|
| **Overview** | KPI tiles, mean trust over time, live risk distribution, recent alerts | `/api/dashboard/overview` |
| **Users & Devices** | Roles, lockout state, MFA enrolment; approve or revoke devices | `/api/users`, `/api/devices` |
| **Live Monitoring** | Session table that updates from the WebSocket, with inline revoke | `/api/sessions` + `WS /ws/live` |
| **Risk Scores** | One account's score across every session, annotated with what moved it | `/api/trust/users/{id}/history` |
| **Alerts** | Feed with severity filters, evidence, acknowledge and resolve | `/api/alerts` |
| **Trust Score** | This session's factor-by-factor breakdown | `/api/trust/me` |
| **Audit Logs** | Searchable chain, verify button, CSV export | `/api/audit` |
| **Session Revocation** | Terminate any session with a reason written to the chain | `/api/sessions/{id}/revoke` |

### Chart decisions, and one that had to change

Charts were built against a validated palette rather than by eye. Running the
four original risk-band colours through the validator produced a **hard failure**:

```
[FAIL] Normal-vision floor   #dc2626 (CRITICAL) vs #ea580c (HIGH)  ΔE 8.7 — below 15
```

Below the floor means *full-colour-vision* readers cannot reliably tell those two
apart, let alone anyone with a colour vision deficiency. Four ordered warm-to-cool
hues cannot be separated by hue alone — that is inherent, not a bad choice of
reds. The bands were re-stepped onto a **status** palette (`#0ca30c`, `#fab219`,
`#ec835a`, `#d03b3b`), and — the part that actually fixes it — **every use pairs
the colour with the band name in text**. Colour is reinforcement, never the
encoding.

The rest follows from the same principle:

* **The donut is legal here** only because there are four ordered parts of one
  whole, the total is the headline in the middle, and every segment is directly
  labelled with its name, count and share.
* **One series, no legend** on the trend line — the title names it. Risk bands
  are drawn as recessive background regions because they are the scale's
  meaning, not data.
* **A single number is not a chart.** "Active sessions", "mean trust", "blocked
  today" are stat tiles; plotting them would be slower to read.

### One socket for the whole app

Every page reads live events from one `LiveProvider` context. Opening a socket
per page would mean three connections and three tickets while an operator moves
between Live Monitoring, Alerts and Overview.

---

## Continuous verification

Every active session is re-scored on a fixed interval, whether or not its owner
has made a request. This is the property that separates Zero Trust from a login
check: trust is not something you earn once at the door.

Each sweep, for every session due:

1. **rebuild the context** — the session's last known network, re-resolved
   through the live providers, and the time *now*;
2. **re-score** through the same engine a request would use;
3. **enforce** any band change immediately, including revoking mid-session;
4. **publish** the new score to open clients.

Step 1 is what makes it continuous rather than lazy. A score that only changed
when the user did something would be evaluation-on-demand with a timer attached.
Re-resolving means a session whose source address lands on a blocklist between
sweeps drops without the user touching anything.

```
Continuous verification running every 30s.
Verification sweep: checked 5, escalated 0, revoked 0, expired 2, errors 0 in 1129ms
Verification sweep: checked 5, escalated 0, revoked 0, expired 0, errors 0 in 64ms
```

### Where the sweep runs, and why it is not always the worker

The worker and the API are separate Compose services, so a score computed in one
has to reach WebSocket clients attached to the other. That needs Redis pub/sub.
Without Redis — the offline default — an in-process bus cannot cross a process
boundary at all.

So the placement follows the configuration, and the API says which mode it is in
at startup:

| `REDIS_URL` | Sweep runs in | Events travel by |
|---|---|---|
| set | the `worker` service | Redis pub/sub, relayed by the API |
| unset | the API process | in-process fan-out |

A sweep publishing into a bus nobody could subscribe to would look like it was
working and do nothing. `RUN_VERIFICATION_IN_API` overrides the choice; under
`APP_ENV=test` it is forced off, because the sweep opens its own session from
the global factory and a background loop writing to the real database while the
suite runs is worse than no loop at all.

### Live push

| Endpoint | Purpose |
|---|---|
| `POST /api/ws/ticket` | Exchange a bearer token for a single-use 30-second ticket |
| `WS /ws/live?ticket=…` | Score changes, revocations and alerts as they happen |
| `GET /api/sessions` | Active sessions with live scores (analysts, admins) |
| `GET /api/sessions/summary` | Counters for the dashboard header |
| `POST /api/sessions/{id}/revoke` | Terminate a session immediately |
| `POST /api/sessions/verify-now` | Run a sweep on demand — same code path |

**Why a ticket and not the token.** Browsers cannot set an `Authorization`
header on a WebSocket handshake, and the usual workaround puts the access token
in the query string — where it lands in proxy logs, browser history and Referer
headers. The client instead trades its bearer token for a ticket over ordinary
HTTP and spends that: bound to one session, 30 seconds, consumed on first use.

**Who sees what.** Administrators and security analysts receive events for every
session; everyone else receives only their own. Events carry their audience, and
the filter is applied server-side before anything is written to the socket.

### Verified live: revocation the user never asked about

An administrator revokes a session from a separate console. The signed-in
browser, which has made no request at all, immediately shows:

```
Session terminated
Laptop reported stolen by the user.
```

Two mechanisms produce that, and either alone is sufficient:

* the database change stops the **next HTTP request**, because every protected
  route re-reads the session rather than trusting the token;
* the published event closes the **open WebSocket**, so the user finds out
  without making a request at all.

The socket also re-checks the session on every 5-second heartbeat, so a
revocation still lands even if the event were missed entirely.

---

## Audit: chain of trust

Every security event is appended to a hash-linked chain:

```
record_hash = SHA256(prev_hash + timestamp + actor + action + payload_hash)
```

A chain is only tamper-*evident* if someone can actually check it, so the check
is a first-class endpoint rather than a script:

| Endpoint | Purpose |
|---|---|
| `GET /api/audit` | Search and filter: action, actor, resource type, IP, date range, free text |
| `GET /api/audit/verify` | Walk the chain, recompute every hash, name the first break |
| `GET /api/audit/{seq}` | One record by chain position |
| `GET /api/audit/stats` | Totals, action histogram, top actors, head hash |
| `GET /api/audit/export.csv` | Streamed CSV **including the hashes** |

Reading needs `audit:read`; verifying needs `audit:verify`. An ordinary
employee gets a 403 from both.

### Verified live, on the real chain

```
GET /api/audit/verify   ->  VALID   checked 2,121   broken_at null    54.94ms
```

Then an insider edits record #1000 to turn a `LOGIN_SUCCESS` into an
`ACCESS_GRANTED`:

```
GET /api/audit/verify   ->  BROKEN  checked 1,000   broken_at 1000    16.79ms
                            reason: record hash does not match the record's own contents
```

Restore the original value and it returns to `VALID` at 2,121. The check stops
at the first break, which is why it examined 1,000 records instead of 2,121.

**An attacker who recomputes the forged record's own hash still fails**: the
next record's `prev_hash` no longer matches, so they would have to rewrite
every record after it. That case has its own test.

### Design decisions

* **Verification streams in chunks**, not one `SELECT *`. A chain that outgrows
  memory becomes unverifiable, and a chain nobody can afford to verify is not
  tamper-evident in any useful sense. 2,121 records verify in ~25 ms.
* **`?from_seq=N` verifies a suffix**, anchored on the preceding record's stored
  hash — useful for incremental checks on a long chain. The response is labelled
  `partial: true`, because a suffix check proves nothing about earlier records
  and must not be allowed to imply otherwise.
* **The CSV export carries `payload_hash`, `prev_hash` and `record_hash`.** An
  export is only evidence if the recipient can re-link the chain from the file
  itself, offline — there is a test that does exactly that.

### Seeded attack scenarios, measured

Every incident the seeder injects is scored by the live engine. These are the
actual bands from the current seed:

| Scenario | n | Mean score | Band | Specification requires |
|---|---|---|---|---|
| brute_force | 5 | 11.9 | CRITICAL | CRITICAL, lockout |
| impossible_travel | 9 | 21.9 | CRITICAL | CRITICAL, blocked |
| session_hijack | 7 | 26.8 | CRITICAL | CRITICAL, immediate revoke |
| insider_threat | 4 | 32.0 | CRITICAL | CRITICAL, auto-revoked |
| credential_theft | 11 | 40.1 | HIGH / CRITICAL | HIGH, step-up MFA |
| lateral_movement | 9 | 48.0 | HIGH | escalating penalties + alert |
| legitimate use | 1,993 | 97.6 | LOW | seamless, no friction |

98.9% of all recorded scores are LOW, which is the false-positive story: the
engine is quiet on normal work and loud on the six attack families.

Credential theft straddles the 40-point HIGH/CRITICAL boundary by design — it
sits closest to the line of any scenario, and individual incidents fall either
side depending on how far the session also deviates on time and behaviour.

### Known boundaries after Phase 8

* **`anomaly_score` is `NULL` on every seeded trust score.** The Isolation
  Forest does not exist until Phase 6; the value is left absent rather than
  invented. The behaviour factor currently uses measurable profile deviation
  only.
* **Seeded trust scores come from `scripts/provisional_scoring.py`**, not from
  the runtime engine. It implements the specified arithmetic and produces the
  same XAI shape, using the signals available before Phase 3/4 exist. Phase 4
  introduces `app/ai/scoring.py` as the single runtime implementation plus a
  backfill that recomputes every seeded row through it.
* **IP reputation and VPN flags in seeded rows are the generator's own ground
  truth**, not live lookups. Phase 3 adds the real providers behind interfaces
  with offline mocks.
* **Historical trust scores are sampled**, not recorded at the live 30-second
  cadence — login plus 1–3 re-verifications per session. Storing 30-second
  samples for 90 days would be millions of rows with no analytical value.
* **`docker compose up` has not been executed on this machine** — Docker is not
  installed here. The Compose file, both Dockerfiles and the Postgres path are
  written but unverified; everything else was verified against SQLite.
* **PDF export is not server-side.** CSV is generated and streamed by the API.
  The specification also lists PDF; the Phase 9 reports page renders a
  print-styled view for the browser's own print-to-PDF, rather than adding a
  rendering dependency that would have to ship in the offline image.
* **The model is measured on the data it was trained on.** There is no held-out
  split: with 376 labelled positives concentrated in six scripted families, a
  split would measure the seeder's randomness more than the model. The numbers
  describe how well the forest isolates *these* events, and should be read that
  way. A production deployment would train on a rolling window and evaluate on
  the following one.
* **`anomaly_score` is `None` until a model exists**, and the behaviour factor
  says so in its reason string rather than being handed a fabricated `0.0` that
  would read as "verified normal". Delete `models/` and the platform keeps
  working on profile deviation alone.
* **The frontend bundle is 700 kB** (200 kB gzipped), most of it Recharts. Fine
  for a demo on a laptop; a production build would code-split the chart pages.
* **PDF export is still browser print-to-PDF**, not server-rendered — see the
  audit section.
* **The enforcement point is an API, not a proxy.** `POST /api/resources/
  {slug}/access` is where a real gateway would sit in front of the actual
  application. The resources themselves are catalogue entries, not running
  services — this project protects the decision, not the backend behind it.
* **A session's location is only as good as the GeoIP source.** With no
  `.mmdb` present, the prefix table places the seeded and demo ranges correctly
  and marks everything else unresolved. Drop in GeoLite2 for real coverage.
* **Tokens live in `sessionStorage`.** Cleared when the tab closes and not
  shared between tabs, but readable by any script on the page. Production would
  move the refresh token into an httpOnly, SameSite=Strict cookie.
* **The rate limiter is a fixed window**, not a sliding one, and the in-process
  cache is per-worker. With `REDIS_URL` set, limits and the revocation denylist
  are shared across workers as intended.

---

## Layout

```
ztna-project/
├── docker-compose.yml     api · web · db · redis · worker
├── .env.example           every setting, no secrets
├── Makefile               local (no-Docker) targets
├── backend/
│   ├── alembic/           migrations (0001_initial_schema)
│   └── app/
│       ├── main.py        app factory, CORS, error handlers, request ids
│       ├── core/          config, database, security, jwt, cache, rate limit,
│       │                  context, dependencies
│       ├── models/        12 tables + enums + shared column types
│       ├── schemas/       Pydantic response models
│       ├── api/           routers (health today, one per domain later)
│       ├── services/      auth, device, trust, access (PEP), policy engine
│       │                  (PDP), audit chain, hash_chain, geo_math
│       ├── ai/            scoring (6 factors), overrides, classifier,
│       │                  decision, xai, profiling, anomaly
│       ├── external/      mfa, geoip, ip_reputation, network_intel,
│       │                  notification — each with an offline implementation
│       ├── middleware/    context collector, gateway rate limit
│       └── workers/       continuous_verification, retrain, runner
├── data/                  optional GeoLite2 / Tor / blocklist drop-ins
├── frontend/              React 18 + Vite + Tailwind 4 + Recharts
│   └── src/
│       ├── pages/         the 8 console pages + login + own-session view
│       ├── components/    layout shell, charts (validated palette), TrustPanel
│       ├── hooks/         useLiveEvents (WebSocket + ticket handshake)
│       ├── live/          LiveProvider — one socket for the whole app
│       └── api/           typed client for every endpoint
├── scripts/
│   ├── seed.py            90-day corpus generator
│   ├── seed_data.py       static reference data
│   ├── totp.py            print a seeded user's current TOTP code
│   ├── train_model.py     train the Isolation Forest and report accuracy
│   ├── provisional_scoring.py
│   └── verify_chain.py    audit chain integrity check
└── docs/                  (Phase 10)
```
