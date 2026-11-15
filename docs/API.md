# API contracts

Base URL: `http://127.0.0.1:8000/api`. JSON request/response bodies. Machine-readable input schemas: [openapi.json](openapi.json), or runtime `/openapi.json`. The OpenAPI response schemas are intentionally generic in v0.1; the response examples and types below, the TypeScript interfaces and API contract tests define their detailed shape.

In authenticated mode, send `Authorization: Bearer TOKEN`. No cookies or wildcard CORS. `scripts/run_local.py` enables a token-free, same-origin loopback mode with a single local administrator identity. It ignores forwarded client headers and rejects non-loopback peers, non-loopback Host names and cross-origin browser requests. It must never be placed behind a remote-access proxy.

| Method / path | Role | Contract |
|---|---|---|
| GET `/health` | Public | Liveness `{status, version}`; not a full DB readiness probe |
| GET `/me` | Viewer+ | `{name, role, local}` |
| POST `/ingest` | Collector/admin | `{events: Envelope[1..200]}` → per-item result below |
| POST `/demo` | Admin | Replays the bundled synthetic demo; exact replay is idempotent |
| GET `/events` | Viewer+ | `{total, items: NormalizedEvent[]}`; `q`, `source`, `offset`, `limit` |
| GET `/events/{id}` | Analyst+ | Full stored event including raw envelope and fingerprint |
| GET `/alerts` | Viewer+ | `{total, items: Alert[]}`; `q`, `severity`, `technique`, `offset`, `limit`; severity first, then event time |
| GET `/cases` | Viewer+ | `{total, items: Case[]}`; `q` (case title), `status`, pagination; descending risk |
| GET `/cases/{id}` | Viewer+ | Case plus alerts, normalized evidence timeline, notes, response requests, evidence manifests |
| PATCH `/cases/{id}` | Analyst+ | Optional `status`, `assignee`; assignee must be a configured analyst/admin or the local identity |
| POST `/cases/{id}/notes` | Analyst+ | `{text}` nonblank, max 5,000 characters; returns note, HTTP 201 |
| PUT `/cases/{id}/checklist` | Analyst+ | `{key, complete}`; four fixed checklist keys |
| POST `/cases/{id}/evidence` | Analyst+ | Frozen case and raw event snapshot; returns `{id, case_id, sha256, created_at, created_by}`, HTTP 201 |
| GET `/evidence/{id}/export` | Analyst+ | Attachment `{sha256, snapshot}`; recomputes integrity first |
| POST `/cases/{id}/responses` | Analyst+ | `{action: "simulate_isolation", reason}`; pending request, HTTP 201 |
| POST `/responses/{id}/approve` | Different admin | Atomically changes pending → simulated; never executes endpoint code |
| GET `/audit` | Analyst+ | Latest `{items: Audit[]}`, optional `case_id`, bounded `limit` |
| GET `/rules` | Viewer+ | Rule metadata, tested syntax, false positives, ATT&CK metadata, observed alert counts |
| GET `/stats` | Viewer+ | Stored-event totals, severity counts, source freshness, host activity and technique signal counts |
| PUT `/iocs` | Admin | `{value: IP, label, source}`; local-only IP lookup database |
| GET `/iocs/lookup?value=IP` | Viewer+ | `{value, match: IOC or null, external_requests: 0}` |

Viewer+ means viewer, analyst or admin; collector credentials do not grant reads. Responses containing raw evidence are restricted to analyst/admin, but normalized command lines and case notes remain visible to viewers. This is not a redaction boundary.

## Ingestion

```json
{"events":[{"source":"synthetic","sensor":"demo-01","payload":{"timestamp":"2026-11-15T09:00:00Z","host":"lab-01","kind":"process","process":"/usr/bin/id","command":"id"}}]}
```

```json
{"accepted":1,"duplicates":0,"rejected":0,"alerts_created":0,"results":[{"index":0,"status":"accepted","event_id":"UUID","alert_ids":[]}]}
```

Duplicates return the original event ID. Rejected items return their array index and a sanitized validation reason. HTTP 200 can contain partial rejection; **always inspect `rejected` and `results`**. Malformed outer schemas yield HTTP 422. Oversized requests yield 413 before JSON parsing. Authentication errors are 401, permission denials 403, missing objects 404, integrity/already-approved conflicts 409, rate limits 429 with `Retry-After`. Database/internal errors roll back the batch rather than silently dropping events.

Timestamps serialize to UTC ISO 8601 with six fractional digits and `+00:00`. `received_at` is server receipt time. Pagination defaults to 50, maximum 200. Source counts and source freshness use stored event receipt time; replaying duplicates does not make an old source appear fresh.

## Event and alert outputs

An event has `{id, timestamp, received_at, source, sensor, host, user, kind, outcome, process, command, parent, src_ip, dst_ip, dst_port, external_id, fields}`. Missing optional values are null. All host/user identifiers are casefolded. Network `fields.destination_scope` is derived from the destination IP, replacing a caller-supplied value.

An alert has `{id, case_id, rule_id, title, severity, confidence, timestamp, created_at, host, user, group_key, techniques, event_ids, explanation, correlation_reason}`. `event_ids` identify the actual evidence. Cases expose `{id, title, status, assignee, first_seen, last_seen, hosts, users, risk, checklist}`. Unknown case fields are rejected on mutation.

The API allows case status corrections, including reopening a closed case. Closing a case excludes it from future correlation. The simulation state machine is stricter: pending → simulated once, with a different approving admin. Local mode is one identity; two-person simulation approval is demonstrated in authenticated mode.
