# Demo script

Twelve minutes, in the order that builds the argument. Everything here is
reproducible from a clean checkout.

## Before the room

```bash
make install          # once
make migrate
python scripts/seed.py --reset
python scripts/train_model.py
make api              # terminal 1
make web              # terminal 2
python scripts/totp.py admin --watch     # terminal 3, leave running
```

Open <http://localhost:5173> and sign in as `admin` / `Admin@Ztna2026!` with a
code from terminal 3. Leave the **Live Monitoring** page projected.

Everything runs offline. No internet is required at any point.

---

## 1. The premise (1 min)

> "Ordinary access control asks *are you who you say you are* once, at the door.
> After that you are trusted until you log out. Zero Trust asks the question
> continuously — and this system asks it every thirty seconds, for every open
> session, whether or not the user does anything."

Point at the sidebar: **live stream connected**. Point at Live Monitoring: the
`verified` column is ticking.

---

## 2. Sign-in is two steps, and the score is explained (2 min)

Open a private window, sign in as `meera.iyer` / `Ztna@Demo2026`.

Note aloud:

- The password step returns **no access token** — only a five-minute MFA
  challenge. A correct password is not an authentication decision.
- The amber banner: *"New device registered as PENDING"*. An unknown device is
  a **risk signal**, not a block. Zero Trust weighs it; it does not lock the
  user out of a new laptop.

Land on the session page. Open **Trust Score**:

> "Every score comes with its arithmetic. Device cost 17 points because this
> fingerprint has never been seen. Behaviour cost 8 because the Isolation Forest
> scores the session 0.55 on a 0–1 anomaly scale. If a panel asks why it is 73,
> the answer is in the record, not reconstructed afterwards."

---

## 3. The seven attacks (5 min)

```bash
python scripts/demo/run_all.py
```

Keep **Live Monitoring** projected — the rows move as the script runs.

| # | Scenario | What to say |
|---|---|---|
| 1 | Credential theft | "Correct password. Unknown machine, new country. Trust falls ~20 points and everything confidential is refused." |
| 2 | Impossible travel | "Coimbatore, then São Paulo minutes later. Location is worth 10 points, so the arithmetic alone can't express this — it's a hard override. CRITICAL, session revoked." |
| 3 | Insider threat | "Valid credentials, approved device, clean network. 75 of the 100 points are untouched. Only the *behaviour* is wrong — and that alone ends the session." |
| 4 | Brute force | "Two defences: the endpoint sheds the burst at 429 and the account locks at 423. The correct password no longer helps." |
| 5 | Session hijack | "A cryptographically perfect token, replayed from Amsterdam. This is exactly what a stateless JWT check cannot catch — the token is bound to the device it was issued to. The real user keeps working." |
| 6 | Lateral movement | "Each refusal is unremarkable. Five of them in one session is the signal, and it compounds." |
| 7 | Legitimate user | "And this is the one that matters most: normal work, no challenge, no friction. 98.9% of all recorded scores are LOW." |

---

## 4. Revocation the user never asked about (2 min)

On **Live Monitoring**, click **Revoke** on the private window's session. Give a
reason — say "laptop reported stolen".

Switch to the private window without touching it:

> **Session terminated — Laptop reported stolen by the user.**

> "That browser made no request. Two mechanisms did this, either sufficient
> alone: the database change stops its next request, because every route
> re-reads the session instead of trusting the token — and the published event
> closed its open socket, so it found out without making one."

---

## 5. The chain of trust (2 min)

Open **Audit Logs** → **Verify chain**.

> "Chain verified — 2,284 records checked in 88 milliseconds, unbroken from
> genesis."

Then break it, live:

```bash
sqlite3 ztna.db "UPDATE audit_logs SET action='ACCESS_GRANTED' WHERE seq=1000;"
```

Click **Verify chain** again:

> "BROKEN at position 1000: record hash does not match the record's own
> contents."

> "And an attacker who recomputes *that* record's hash still fails, because the
> next record's `prev_hash` no longer matches. They would have to rewrite every
> record after it."

Put it back:

```bash
sqlite3 ztna.db "UPDATE audit_logs SET action='LOGIN_SUCCESS' WHERE seq=1000;"
```

---

## Questions to expect, and the honest answers

**"Isn't 84.6% precision poor?"**
It is unsupervised — the model never sees the labels. And recall is what matters
here: a missed attack is a breach, a false positive is one extra MFA prompt.
Recall is 94.9%, and the 19 misses are still caught by the deterministic factors.

**"Why does impossible travel need a special case?"**
Because the specification caps each factor's influence, and location is worth
10 points. That cap is right — one signal should not dominate — but it means
graded arithmetic cannot express *proof* that two sessions are not the same
person. Six conditions bypass it, each recording its own reason.

**"Could someone forge a device fingerprint?"**
Yes. It is an identifying signal, not a secret — anything the browser reports,
an attacker can forge. Its value is that forging it *correctly* requires knowing
the victim's exact environment, so a mismatch is strong evidence a token has
moved. It is never trusted alone; it is one input of six.

**"What happens if GeoIP or AbuseIPDB is down?"**
The signal degrades, the request proceeds. An external outage must never be able
to lock everyone out. `/health` reports which implementation is answering.

**"Is the model measured on its own training data?"**
Yes, and that is stated in the report. With 376 positives across six scripted
families, a held-out split would measure the seeder's randomness more than the
model. Production would train on a rolling window and evaluate on the next.
