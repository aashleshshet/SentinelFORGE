# Modernization security review — 2026-11-15

The modernization preserves the local/authenticated/public-demo trust boundaries. No exploitable critical or high-severity regression was identified in this targeted review. One existing hosting-layer gap was fixed: the Vercel static HTML did not receive the security headers already supplied by FastAPI. This is a scoped source/configuration review with tests and dependency checks, not a penetration test or proof that the application is vulnerability-free.

## SF-01 — Missing static frontend browser protections (Medium, fixed)

- **Rules:** REACT-CSP-001, REACT-HEADERS-001.
- **Evidence:** a production HEAD request before modernization returned HTTP 200 for `/` with no Content-Security-Policy, X-Frame-Options, X-Content-Type-Options or Referrer-Policy. FastAPI's middleware at `backend/sentinelforge/api.py:80` already supplied these, but Vercel serves frontend assets separately.
- **Impact:** framing and script execution lacked the intended browser defense-in-depth on the public HTML shell. No XSS exploit or unauthorized data access was demonstrated.
- **Fix:** `vercel.json:41` adds same-origin CSP, frame denial, nosniff, no-referrer and restricted camera/microphone/geolocation permissions at public ingress. Scripts allow neither unsafe-inline nor unsafe-eval. The existing style-only unsafe-inline exception is retained for API-derived chart widths; this change does not weaken the API policy.
- **Verification:** local compiled browser tests run under FastAPI's matching CSP. Production header and browser verification is recorded in `MODERNIZATION.md` after deployment.

## SF-02 — Static operator credentials (existing limitation, Medium outside the trusted lab)

- **Rules:** REACT-AUTH-001 / FASTAPI-AUTH-002.
- **Evidence:** `backend/sentinelforge/config.py:10` defines named role/token identities with length validation; `backend/sentinelforge/api.py:168` compares bearer tokens without an expiry mechanism. Tokens are kept only in React memory and are not written to localStorage, sessionStorage, URLs or logs.
- **Impact:** a stolen operator token remains usable until the operator rotates configuration and restarts. There is no MFA or central session revocation.
- **Disposition:** documented, unchanged to preserve the explicitly requested local workflow. The public deployment ignores operator identities and denies mutations. Before any remote editable deployment, use a reviewed identity/session system with scoped, expiring credentials and MFA. Do not expose token-free loopback mode.

## SF-03 — Retained-data growth and per-process limits (existing limitation, Low in the local lab)

- **Rule:** FASTAPI-LIMITS-001.
- **Evidence:** `backend/sentinelforge/api.py:567` loads retained alerts for aggregate statistics; `api.py:33` keeps rate-limit state in process memory. No automatic retention or global quota is implemented.
- **Impact:** large operator datasets can increase query cost and disk use. Multiple processes do not share limiter state.
- **Disposition:** unchanged in this UI scope. The public demo has a fixed 18-event snapshot. Add retention, aggregate queries/indexes, load testing and distributed/edge controls before broad operational ingestion.

## Checks and preserved controls

- **Access control:** all data/mutation endpoints reviewed for explicit role dependencies. Public mutations are denied before body parsing, and SQLite query-only mode independently rejects writes. Two-person response approval remains enforced server-side.
- **Route safety:** `/how-it-works` serves one fixed build path. It is not an API/asset catch-all. Regression tests check authenticated API denial, missing asset/API 404s and rejected POST on the document route.
- **XSS and redirects:** no new raw HTML sinks, eval, string-to-code, third-party script loading or unsafe URL construction. Query view values are allowlisted. Evidence and notes remain escaped React text. External links use constant HTTPS destinations with noreferrer.
- **Injection and input:** SQLAlchemy parameterization, literal query escaping, safe YAML, bounded JSON/event/text fields and no command-execution handler. Browser JSON validation remains backed by server validation. New import tests cover invalid structure and duplicate batches.
- **Privacy:** no cookies, persistent browser token storage, analytics or external reputation requests were added. Existing telemetry/error logging exclusions remain intact. The reviewer did not print environment credentials.
- **Secrets:** 103 tracked/unignored files at the pre-release scan were checked for common credential/private-key patterns; no matches. Test-only fixture credentials and non-credential local/public placeholders are intentional. Pattern scans are not exhaustive secret detection.
- **Dependencies:** pip-audit against requirements.lock reported no known vulnerabilities; pnpm audit reported zero in all categories. Axe 4.14.0 is the only new development dependency, installed from the official maintained package with installation scripts disabled. No new production library.
- **Deployment boundary:** existing Vercel Services, isolated public app entrypoint, Docker internal networks and loopback binding remain intact. The review did not alter credentials, databases or production environment values.

## Review limits

The available security-best-practices skill supplied React, generic browser and FastAPI guidance. The Codex Security plugin was not available, and attempted parallel reviewers hit an account usage limit; no independent agent/security scanner result is claimed. Browser checks use Chromium, not a full browser/device matrix. Automated accessibility and dependency checks do not establish certification, legal custody, secure production tenancy or complete vulnerability coverage. Existing signed-collector, retention, encryption-at-rest, least-privilege DB and external audit limitations remain documented in SECURITY.md and THREAT_MODEL.md.
