# Security policy and deployment boundary

SentinelForge is an experimental local security lab. Do not expose it publicly or ingest production secrets without a security review and deployment controls. The shipped Compose port binds only to `127.0.0.1`.

## Local mode

The user-requested `python scripts/run_local.py` workflow intentionally requires no token. It binds loopback, disables forwarded-address trust and checks the request peer, Host, Origin and cross-site Fetch Metadata. This grants every local program access as a shared administrator. It is suitable for this trusted-computer demo, never for a public service, SSH tunnel shared with others, or reverse proxy. Authenticated mode remains the default for the normal ASGI entry point and Docker deployment. Two-person approval requires authenticated mode because local mode has one identity.

## Implemented controls

- Unique, randomly generated bearer credentials; 32-character minimum; duplicate names/tokens rejected at startup. No built-in usable password. Constant-time token comparison. Browser storage is memory only.
- Roles: viewer reads normalized data/cases/rules; analyst additionally updates cases, writes notes, preserves/exports raw evidence and requests simulations; admin additionally ingests, updates IOC data and approves another person's simulation; collector only ingests.
- Raw evidence/export is analyst/admin only. Viewer access still reveals potentially sensitive command lines and identities; it is not a public or redacted role.
- A different administrator must approve a simulation. No real endpoint integration exists. API input cannot request another response type.
- A 1 MiB request cap, 64 KiB payload cap, 200-event batch cap, bounded text fields, validated IP/port/timestamp, parameterized SQLAlchemy queries, no arbitrary SQL or `eval`, safe YAML loading, no uploaded rules endpoint.
- In-memory IP limiter (120 API requests/minute), bounded to 10,000 IP entries, direct peer IP rather than untrusted forwarded headers. Appropriate for one local process, not distributed rate enforcement.
- Structured request logs include generated request ID, method, status, and duration; omit tokens, body, query strings and notes. Audit records retain actor and operation without copying note text.
- React escapes evidence and notes; CSP restricts scripts/assets to the same origin. No third-party fonts, analytics, network enrichment or telemetry upload.
- Non-root, read-only API container; private database network, no DB host port; runtime dependencies separately pinned.

## Known security limitations

Static tokens have no expiry, MFA or centralized revocation; rotate a token in `.env` and restart. Tokens live in process/container environment and are accessible to an administrator. No tenant isolation or host-level permission model. Collectors can lie about source attribution, and signed events are not implemented. TLS termination, distributed limits and request-timeout defenses require an external proxy before remote access. The default schema-owning DB user is not a least-privilege production role.

Audit/evidence tables have no update/delete API, but a database administrator can alter them. SHA-256 detects snapshot inconsistency against its saved hash; it does not prove authorship or protect against someone replacing both. Use externally signed manifests, WORM storage and documented custody for forensic requirements. No retention/deletion job, disk quota or archive workflow is included. Restrict access and plan data retention before real telemetry.

The API validates supported fields; detection output remains untrusted until investigated. OpenAPI is public and describes routes without disclosing tokens or stored telemetry. Error details avoid raw event dumps. Browser tokens can still be stolen by an XSS vulnerability, so front-end dependency and CSP review remain necessary.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting if enabled for this repository. Otherwise contact the repository maintainer privately to establish a secure channel. Do not post credentials, raw telemetry, exploit details or customer data in public issues. There is no response-time SLA or supported production release line.

Run `pip-audit -r requirements.lock` and `pnpm --dir frontend audit --audit-level high` to refresh dependency scans. A clean scan is not a security audit. Review [THREAT_MODEL.md](docs/THREAT_MODEL.md) and [VALIDATION.md](docs/VALIDATION.md).
