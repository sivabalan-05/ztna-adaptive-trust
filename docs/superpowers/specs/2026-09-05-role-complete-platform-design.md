# Role-complete platform: real resources, gated content, and a portal for every role

**Status:** approved design, ready for implementation planning
**Date:** 2026-09-05

## Problem

The backend implements a complete Zero Trust platform. The frontend exposes it
to exactly one role.

Signing in as `arjun.krishnan` (an `employee`) lands on a single screen showing
session details, trust factors and a device table. Beside it sits a sidebar of
eight items that are not links at all — plain `<div>`s carrying
`title="Available in Phase 9"`. Nothing else in the product is reachable for
that account. The same is true for `contractor`.

`security_analyst` has the opposite failure. That role is routed into the full
operator console, but its permission set omits `users:write`,
`devices:approve`, `devices:revoke` and `policies:write`. The console renders
those controls unconditionally, so role dropdowns, unlock buttons and device
approve/revoke buttons appear live and then fail with HTTP 403.

Three capabilities that exist and work in the API have no interface anywhere:

| Capability | API | UI today |
| --- | --- | --- |
| Policy enforcement point | `POST /api/resources/{slug}/access` | none |
| Resource catalogue with live reachability | `GET /api/resources` | none |
| A caller's own access history | `GET /api/resources/access/history` | none |
| A caller's own sessions | `GET /api/sessions/me` | none |
| Policy administration | `/api/policies` full CRUD | none |

The enforcement point is the centre of the project's thesis and today can only
be exercised by the seven demo scripts.

Finally, resources are metadata only. A `Resource` row has a name, a
sensitivity and a trust floor, but no content. "Granting access" therefore
grants access to nothing, which makes the end-to-end story impossible to show.

## Goals

1. Resources carry real files that an administrator uploads through the browser.
2. Viewing or downloading a file is itself a policy decision, evaluated live.
3. Every role has a complete, functioning interface with no placeholder UI.
4. Controls a role cannot use are never rendered for that role.

## Non-goals

- No object storage, CDN or external file service. The platform stays offline-capable.
- No versioning or revision history for uploaded files.
- No self-service resource creation for non-administrators.
- No frontend test harness. The project has none; adding one is a separate decision.

## Design

### 1. Resource content

Migration `0002_resource_content` adds six nullable columns to `resources`:

| Column | Type | Notes |
| --- | --- | --- |
| `file_name` | `String(255)` | the original filename, sanitised |
| `file_path` | `String(512)` | relative to the storage root; never client-supplied |
| `content_type` | `String(128)` | validated against the allowlist below |
| `file_size` | `Integer` | bytes, recorded at upload |
| `uploaded_at` | `TZDateTime` | |
| `uploaded_by_id` | FK `users.id`, nullable | `ON DELETE SET NULL` |

All are nullable, so the twelve existing rows migrate untouched and a resource
without a file remains valid — it simply has no content to serve.

Bytes live on disk, not in the database: `storage/resources/<uuid4>.<ext>`,
under a root configured by `settings.resource_storage_dir` (default
`<project>/storage/resources`, created on demand, gitignored). Database blobs
were rejected because SQLite reads a `LargeBinary` fully into memory and would
bloat the single `ztna.db` file that the project's offline design depends on.

The stored filename is always a server-generated UUID. The client's filename is
kept only as a display label in `file_name`, so a hostile upload name cannot
influence a path.

### 2. Content delivery is an enforcement decision

`GET /api/resources/{slug}/content` calls `AccessService.request_access()` — the
same function the enforcement point uses — before it streams a single byte.

A request therefore:

1. re-scores the session against the context of *this* request;
2. runs role clearance, policy and trust gates;
3. writes an `access_requests` row with the score, decision, matched policy,
   deciding gate, latency and feature vector;
4. appends the decision to the hash-chained audit log;
5. streams the file only if the decision granted it.

A denial returns 403 carrying the deciding gate in `X-Access-Gate` and the
reason in the body, and commits the evidence before raising, matching the
existing behaviour of `POST /{slug}/access`.

No static mount and no direct path ever exposes `storage/`. The only route to
the bytes runs through the enforcement point. Consequently, revoking a device
or driving a user's trust score down mid-session causes their *next* download to
fail — the property the whole project argues for, now demonstrable from the UI.

Because the browser must send an `Authorization` header, the frontend fetches
content as a blob through the existing axios instance rather than a plain
anchor, then previews it from an object URL or saves it.

### 3. Administration endpoints

All require `resources:write`, held only by `admin`.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/resources` | create; multipart metadata plus optional file |
| `PATCH` | `/api/resources/{slug}` | edit metadata |
| `POST` | `/api/resources/{slug}/file` | attach or replace the file |
| `DELETE` | `/api/resources/{slug}` | disable (`enabled = false`) |

`DELETE` disables rather than destroys. `access_requests` rows reference
resources, and the audit trail must stay intact; a disabled resource leaves the
catalogue and is refused by the enforcement point.

Validation at the boundary: 25 MB ceiling, content-type allowlist (PDF, plain
text, Markdown, CSV, JSON, PNG, JPEG, WebP, and the OpenXML document types),
slug matching `^[a-z0-9-]+$` and unique, `min_trust_score` within 0–100
defaulting to the sensitivity floor, and rejection of any upload whose declared
type is outside the allowlist.

### 4. The non-operator portal

`SessionPage` stops being the entire non-operator experience. `App.tsx` routes
`employee` and `contractor` into a `PortalShell` with real routes:

| Route | Screen | Data |
| --- | --- | --- |
| `/` | My Access | `GET /api/resources`, `POST /{slug}/access`, `GET /{slug}/content` |
| `/session` | My Session | `GET /api/auth/me`, `GET/POST /api/trust/me` |
| `/devices` | My Devices | `GET /api/devices/me` |
| `/activity` | My Activity | `GET /api/resources/access/history`, `GET /api/sessions/me` |
| `/trust` | Trust & Policy | `GET /api/trust/config`, `GET /api/trust/me` |

**My Access** groups the catalogue by sensitivity (PUBLIC → RESTRICTED). Each
resource shows its reachability as computed by the server, and opening one
displays the decision: granted or denied, the deciding gate, the matched
policy, the score at that moment against the score required, and the policies
evaluated. When granted and the resource has a file, the content is previewed
inline with a download control alongside.

Preview adds no rendering dependency. Text-family content (plain text,
Markdown, CSV, JSON) is displayed as monospaced text, Markdown as its source
rather than rendered HTML. PDFs and images are shown in a native `<object>` or
`<img>` from the blob's object URL. Any other allowed type offers download
only.

**My Session** carries over the existing trust panel, session fields and device
table unchanged in substance.

**Trust & Policy** explains the score using the live weights and bands from
`/api/trust/config` rather than restating them in the frontend, and names what
would raise the user into the next band.

No screen contains a disabled or "coming soon" element.

### 5. Permission-aware operator console

A `usePermissions()` hook derives capability from `me.permissions` and
`me.is_admin`. Every write control is gated on the specific permission it
needs, so `security_analyst` sees a coherent read-and-revoke console rather
than buttons that 403:

| Control | Permission |
| --- | --- |
| Change user role, unlock account | `users:write` |
| Approve or revoke a device | `devices:approve` / `devices:revoke` |
| Revoke a session | `sessions:revoke` |
| Create, edit or disable a policy | `policies:write` |
| Create, edit or upload a resource | `resources:write` |

Two operator screens are added:

- **Resources** — the catalogue with create, edit, upload and disable for
  administrators; read-only for analysts.
- **Policies** — list, create, edit and enable/disable over the existing
  `/api/policies` API; read-only for analysts.

### 6. Seed data

The seeder attaches a small generated file to each of the twelve resources so a
fresh `python scripts/seed.py --reset` yields a catalogue that can actually be
opened. `--reset` clears the storage directory alongside the tables so the two
never drift apart.

Seeded files are written as text, Markdown, CSV or JSON only — never PDF. The
project deliberately carries no server-side document-rendering dependency (the
same reason its report export is browser print-to-PDF), and the seeder must not
introduce one. Administrators may still upload PDFs; the platform stores and
serves them without rendering them.

## Error handling

- Upload rejections return 422 naming the failing constraint (size, type, slug).
- A resource with no file returns 404 from `/content` with an explicit message,
  distinct from a policy denial's 403.
- A denial commits its evidence before raising, as the existing enforcement
  point does.
- Frontend surfaces the API `detail` string; blob-fetch failures are decoded
  from the error body rather than shown as a generic failure.
- A missing file on disk whose row exists returns 500 and logs the orphaned
  path; the seeder and delete paths are responsible for keeping them in step.

## Testing

Backend, test-first, in the existing pytest suite:

- upload accepted within the cap and allowlist; rejected outside either
- slug uniqueness and pattern enforcement
- `POST /api/resources` refused without `resources:write` for `employee`,
  `contractor` and `security_analyst`
- `/content` granted for a permitted role, and the file bytes match
- `/content` denied by clearance for a `contractor` against a CONFIDENTIAL resource
- `/content` denied by trust when the score sits below the resource floor
- a session granted a download, then denied on the next attempt after its trust
  score drops — the continuous-verification property, asserted directly
- every `/content` call writes an `access_requests` row and an audit entry
- disabled resources leave the catalogue and are refused
- migration `0002` upgrades and downgrades cleanly against a seeded database

Frontend verification is manual and per role in the browser — `admin`,
`security_analyst`, `employee`, `contractor` — because the project has no
frontend test harness.

## Risks

- **Trust floors may make RESTRICTED resources unreachable in practice.** A live
  session on a new device scored 68 during this investigation, below the
  CONFIDENTIAL floor of 75. This is correct behaviour, but the demo needs an
  approved device to show a successful high-sensitivity download. Worth stating
  in the demo script rather than tuning the thresholds.
- **Storage and database can drift.** Mitigated by disabling rather than
  deleting, by clearing storage on `--reset`, and by logging orphaned paths.
