# Trust scoring

## The formula

```
trust_score = clamp(0, 100, 100 − Σ (penalty_i × weight_i / 100))
```

Start at 100. Each factor computes a normalised penalty of 0–100, scaled by its
weight. Nothing is ever added back.

| # | Factor | Weight | Signals |
|---|---|---|---|
| 1 | Identity | 25 | password strength, MFA outcome, failed-login streak, credential age, account status |
| 2 | Device | 20 | known vs unknown fingerprint, approval state, OS/browser drift, first-seen recency |
| 3 | Network | 20 | IP reputation, VPN/proxy/Tor, ASN type, mid-session IP change |
| 4 | Behaviour | 20 | Isolation Forest anomaly score, profile deviation, request-rate spike, unusual or denied resource access |
| 5 | Location | 10 | distance from usual, new country, impossible travel |
| 6 | Temporal | 5 | login hour vs typical window, weekend access, duration outlier |

| Score | Risk | Action |
|---|---|---|
| 80–100 | LOW | ALLOW — full access per role |
| 60–79 | MEDIUM | ALLOW_LIMITED — read-only, sensitive resources hidden |
| 40–59 | HIGH | STEP_UP_MFA — re-authenticate to continue |
| 0–39 | CRITICAL | BLOCK + REVOKE_SESSION + alert |

Resource sensitivity raises the bar independently: `PUBLIC 0`, `INTERNAL 60`,
`CONFIDENTIAL 75`, `RESTRICTED 90`.

## Hard overrides, and why they are necessary

Capping each factor's influence has a consequence worth stating plainly:

- **Location is worth 10 points**, so impossible travel on its own can cost at
  most 10.
- **An insider** with valid credentials, an approved device and a clean network
  has 75 of the 100 points untouched. The arithmetic alone cannot put them
  below roughly 77 however anomalous their behaviour is.

The weighted sum expresses *graded* risk. A small set of conditions are not
graded risk at all — they are evidence that the session is not who it claims to
be, or that an account is under attack. Those clamp the score, and each records
its own reason so the dashboard can explain why a score ignored the arithmetic.

| Override | Clamps to | Fires when |
|---|---|---|
| `account_lockout` | 18 | failed logins ≥ threshold and MFA not passed |
| `impossible_travel` | 22 | implied speed > 900 km/h between consecutive sign-ins |
| `session_hijack` | 28 | mid-session IP change **and** unknown fingerprint |
| `malicious_ip` | 30 | abuse confidence ≥ 90 |
| `mass_enumeration` | 32 | ≥ 8 distinct resources **and** ≥ 2.5× the account's baseline |
| `privilege_probing` | 48 | ≥ 5 policy denials in one session |

Each requires **two** conditions where one alone would be ordinary. A roaming
user changes IP without being a hijack; a busy administrator touches many
resources without being an insider.

### The enumeration thresholds are calibrated to the catalogue

They were originally 20 resources and 5×, taken from the seeded attack narrative
where an insider opens "40 confidential files". This deployment publishes
**twelve** resources, so a floor of 20 could never be reached and the override
was dead code. In a twelve-resource system, touching ten when you normally touch
four *is* mass enumeration. A deployment with thousands of resources should
raise both numbers. There is a test asserting the floor stays reachable.

## Explainability

Every evaluation returns, per factor: the raw signals it looked at, its weight,
the penalty, the points deducted and a plain-English reason. A bare number is
never returned.

```
score 73.5  MEDIUM  ALLOW_LIMITED
  identity  w=25    0.0   Nothing unusual observed for this factor.
  device    w=20  −17.0   Device fingerprint has never been seen on this account.
  network   w=20    0.0   Nothing unusual observed for this factor.
  behavior  w=20   −6.5   Session deviates from this account's behaviour profile.
  location  w=10    0.0   Nothing unusual observed for this factor.
  temporal  w=5    −3.0   Signed in at 16:00, 6.9 hours outside the usual window.
```

When an override fires, the breakdown gains an `override` row recording the
pre-clamp weighted score, so a reviewer can see what the arithmetic said before
the clamp.

## Anomaly detection

Isolation Forest, 13 features, `n_estimators=200`, `contamination=0.05`,
`random_state=42`.

| | |
|---|---|
| Temporal | `hour_sin`, `hour_cos`, `day_of_week` |
| Device | `is_known_device` |
| Location | `geo_distance_from_usual_km`, `is_new_country`, `travel_velocity_kmh` |
| Network | `ip_reputation_score`, `is_vpn` |
| Activity | `requests_per_minute`, `session_duration_min`, `num_distinct_resources` |
| Identity | `failed_auth_count_24h` |

Hour is sin/cos encoded so 23:00 and 00:00 sit adjacent in feature space.
Features are stored on every `access_requests` row at write time, so the model
trains on the numbers the engine actually saw rather than on a reconstruction.

### Measured accuracy

8,435 events, 376 (4.5%) labelled attacks:

| Metric | Value |
|---|---|
| Precision | 0.846 |
| Recall | 0.949 |
| F1 | 0.895 |
| ROC-AUC | 0.997 |
| Average precision | 0.975 |

Confusion matrix: TP 357 · FP 65 · FN 19 · TN 7,994.

**Read these correctly.** Isolation Forest is *unsupervised* — it never sees the
labels. They exist only to measure it afterwards. So this answers "how well does
an algorithm told nothing about attacks happen to isolate the ones we planted?",
not "how well did it learn them."

It also explains why **recall is the metric to optimise**: a missed attack is a
breach, a false positive is one extra MFA prompt. The 19 events the model misses
are still caught by the deterministic factors and the overrides — the forest
contributes to one factor of six.

### Per-user models: trained, measured, not used

All 25 accounts clear the 50-event threshold and all 25 models are trained. They
are **measurably worse**: mean recall 0.624, mean F1 0.394, against 0.949 and
0.895 global. Each account carries only a handful of labelled attacks, so a
per-account `contamination` of 5% is a poor fit for the real per-account rate.
`USE_PER_USER_MODELS` defaults to `false`. Shipping a worse detector to satisfy
a checkbox would be the wrong call; the setting exists so the trade-off can be
re-tested as real traffic accumulates.

## Known calibration boundaries

- **The model is measured on the data it was trained on.** No held-out split:
  with 376 positives concentrated in six scripted families, a split would
  measure the seeder's randomness more than the model. A production deployment
  would train on a rolling window and evaluate on the following one.
- **Live sessions score mildly anomalous in their first seconds.** The corpus is
  seeded *session aggregates*, where `session_duration_min` and
  `requests_per_minute` describe complete sessions. A session one second old has
  a duration near zero and a rate equal to its request count — values the model
  never saw as normal, so it scores around 0.55 on a legitimate sign-in. The
  nightly retrain folds live events into the corpus and recalibrates this; it is
  a cold-start artefact, not a modelling error.
- **`anomaly_score` is `None` until a model exists**, and the behaviour factor
  says so in its reason string rather than being handed a fabricated `0.0` that
  would read as "verified normal".
