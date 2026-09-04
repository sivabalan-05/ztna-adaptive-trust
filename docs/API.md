# API reference

Base URL `http://localhost:8000`. Interactive documentation at `/docs`.

## Authentication

Login is two-step. A correct password is not an authentication decision; it
earns a five-minute MFA token that grants no access on its own.

```bash
# 1. password — returns an MFA token, never an access token
curl -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -H 'X-Device-Fingerprint: <sha256 of the device signals>' \
  -d '{"username":"admin","password":"Admin@Ztna2026!"}'

# 2. TOTP — returns the access + refresh pair
curl -X POST http://localhost:8000/api/auth/mfa/verify \
  -H 'Content-Type: application/json' \
  -H 'X-Device-Fingerprint: <same fingerprint>' \
  -d '{"mfa_token":"<from step 1>","code":"123456"}'
```

Every subsequent request carries `Authorization: Bearer <access_token>` **and**
the same `X-Device-Fingerprint`. The token is bound to the device it was issued
to; presenting it from another one is refused.

Get a code for a seeded account during a demo:

```bash
python scripts/totp.py admin --watch
```

## Headers the gateway reads

| Header | Purpose |
|---|---|
| `Authorization` | `Bearer <access token>` |
| `X-Device-Fingerprint` | SHA-256 over user agent, platform, screen, timezone, language, canvas/WebGL |
| `X-Device-Platform`, `X-Device-Screen`, `X-Device-Timezone` | Fingerprint components, kept for consistency checking |
| `X-Forwarded-For` | Honoured for exactly one hop; only the leftmost entry is trusted |
| `X-Request-ID` | Echoed back on every response for tracing |

## Errors

One shape, always. Never a stack trace.

```json
{ "detail": "Session is bound to a different device.",
  "code": "http_401",
  "request_id": "4b118abfb3ec47c19c6a3714977bcf5b" }
```

Headers carry meaning the client needs: `WWW-Authenticate` says *why* a 401
happened (so a browser knows whether refreshing would help), `Retry-After` paces
a 429, and `X-Access-Gate` names which policy gate refused a 403.

## Endpoints

### alerts

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/alerts` | Alert feed, newest first |
| `GET` | `/api/alerts/stats` | Alert counters |
| `GET` | `/api/alerts/{alert_id}` | One alert |
| `POST` | `/api/alerts/{alert_id}/acknowledge` | Acknowledge an alert |
| `POST` | `/api/alerts/{alert_id}/resolve` | Resolve an alert |

### audit

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/audit` | Search the audit log |
| `GET` | `/api/audit/export.csv` | Export the filtered audit log as CSV |
| `GET` | `/api/audit/stats` | Audit log summary |
| `GET` | `/api/audit/verify` | Verify the hash chain end to end |
| `GET` | `/api/audit/{seq}` | One record by chain position |

### authentication

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/login` | Step 1 — verify the password |
| `POST` | `/api/auth/logout` | End the current session |
| `GET` | `/api/auth/me` | Current identity and session |
| `POST` | `/api/auth/mfa/confirm` | Confirm TOTP enrolment with a code from the app |
| `POST` | `/api/auth/mfa/enrol` | Generate a TOTP secret and enrolment QR code |
| `POST` | `/api/auth/mfa/verify` | Step 2 — verify the TOTP code and issue tokens |
| `POST` | `/api/auth/refresh` | Rotate tokens |
| `POST` | `/api/auth/register` | Create a user (administrators only) |

### dashboard

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/dashboard/overview` | Everything the overview needs |

### devices

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/devices` | All devices (analysts, admins) |
| `GET` | `/api/devices/me` | Your registered devices |
| `POST` | `/api/devices/{device_id}/approve` | Approve a pending device |
| `POST` | `/api/devices/{device_id}/revoke` | Revoke a device |

### health

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Service health |

### live

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/ws/ticket` | Exchange a bearer token for a WebSocket ticket |

### meta

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | API index |

### policies

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/policies` | All policies, highest priority first |
| `POST` | `/api/policies` | Create a policy |
| `PATCH` | `/api/policies/{policy_id}` | Update a policy |
| `DELETE` | `/api/policies/{policy_id}` | Delete a policy |

### resources

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/resources` | The catalogue, annotated with what this session can currently reach |
| `GET` | `/api/resources/access/history` | The caller's recent access attempts |
| `GET` | `/api/resources/{slug}` | One resource |
| `POST` | `/api/resources/{slug}/access` | Request access — the policy enforcement point |

### sessions

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/sessions` | Active sessions (analysts, admins) |
| `GET` | `/api/sessions/me` | Your own sessions |
| `GET` | `/api/sessions/summary` | Live counters |
| `POST` | `/api/sessions/verify-now` | Run a verification sweep immediately |
| `GET` | `/api/sessions/{session_id}` | One session |
| `POST` | `/api/sessions/{session_id}/revoke` | Terminate a session immediately |

### trust

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/trust/config` | Scoring weights, risk bands, sensitivity floors and overrides |
| `GET` | `/api/trust/me` | The most recent score for the caller's session |
| `POST` | `/api/trust/me/evaluate` | Re-score the caller's session right now |
| `GET` | `/api/trust/sessions/{session_id}` | Latest score for any session (analysts, admins) |
| `GET` | `/api/trust/sessions/{session_id}/history` | Every recalculation for a session, oldest first |
| `GET` | `/api/trust/users/{user_id}/history` | A user's score over time across all sessions |

### users

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/users` | All users |
| `GET` | `/api/users/roles` | Available roles |
| `GET` | `/api/users/{user_id}` | One user |
| `PATCH` | `/api/users/{user_id}` | Update a user |

## Permissions

| Permission | Held by |
|---|---|
| `users:read`, `users:write` | admin |
| `devices:read`, `devices:approve`, `devices:revoke` | admin, analyst (read only) |
| `policies:read`, `policies:write` | admin |
| `sessions:read`, `sessions:revoke` | admin, security_analyst |
| `alerts:read`, `alerts:write` | admin, security_analyst |
| `audit:read`, `audit:verify` | admin, security_analyst |

Administrators pass every check. Everyone else is checked against their role's
list, and a user may always read their own session and devices.

## WebSocket

Browsers cannot set an `Authorization` header on a WebSocket handshake, and
putting a bearer token in the query string leaves it in proxy logs and browser
history. Trade the token for a ticket instead:

```bash
curl -X POST http://localhost:8000/api/ws/ticket -H 'Authorization: Bearer <token>' ...
# → {"ticket":"…","expires_in":30,"url":"/ws/live"}
```

Then connect to `ws://localhost:8000/ws/live?ticket=<ticket>`. The ticket is
single-use and expires in 30 seconds.

Message types: `connected`, `heartbeat`, `session.score`, `session.revoked`,
`session.expired`, `session.terminated`. Administrators and analysts receive
events for every session; everyone else receives only their own, filtered
server-side before anything reaches the socket.

## Rate limits

| Bucket | Limit | Keyed on |
|---|---|---|
| Gateway | 300 / min | source address |
| Login | 10 / min | source address **and** username |
| MFA verify | 8 / min | source address |
| Refresh | 30 / min | source address |

`/health` and `/docs` are exempt, so a busy API is never marked unhealthy by its
own throttle.
