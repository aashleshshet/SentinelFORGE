# Threat model

Scope: a single-tenant local lab with untrusted imported telemetry, a React browser, one FastAPI process, PostgreSQL or SQLite, an operator-managed rules directory and a bundled MITRE subset. A public multi-tenant service is outside scope.

| Threat / boundary | Existing control | Residual exposure |
|---|---|---|
| Unauthenticated API caller → data | Bearer tokens and explicit role checks by default | Static tokens lack MFA/expiry; trusted operators can read configured secrets |
| Token-free local caller → data | Explicit local mode; forced loopback bind, no proxy-header trust; loopback peer/Host and same-origin checks | Any local process/user with access to loopback can act as the shared local admin; never proxy this mode remotely |
| Malicious website → localhost | No wildcard CORS, cross-site fetch/origin rejection in local mode, protected mode uses non-cookie bearer headers | Hostile local programs can bypass browser restrictions; they are within the local trust boundary |
| Viewer → raw evidence or mutation | Server-side analyst/admin checks | Normalized command lines and notes are visible to viewers |
| Compromised collector → forged attribution | Source adapter, fixed envelope attribution, validated fields, actor audit | Collector can claim another sensor/host; no signing or sensor identity binding |
| Telemetry → parser/resource exhaustion | Streaming body cap, per-record cap, bounded batch and strings, IP limiter | No global quotas, durable queues or distributed rate limiter; deeply pathological JSON and slow-client protection require proxy hardening |
| Telemetry → executable code | No shell execution, no eval, safe YAML, escaped React rendering | The detector only understands supported formats; unusual inputs may expose untested parser cases |
| Input → database queries | SQLAlchemy parameterization, literal escaping for contains filters | Broad list/stat queries scan retained alerts; large datasets need indexes/search redesign and retention |
| Concurrent ingestion → duplicate cases/alerts | Shared writer lock, DB unique fingerprint, PostgreSQL advisory transaction lock | SQLite multiple processes unsupported; lock limits throughput |
| Analyst → unauthorized response | Simulation-only enum, separate-admin approval, atomic state change, audit | Real endpoint response has no adapter and must not be retrofitted without a review |
| Database admin → evidence alteration | Stored snapshot hash; API exposes no edit/delete operation | Both data and hash can be changed by an administrator; not signed/WORM storage |
| IOC → third-party disclosure / SSRF | Local IP database only; no provider HTTP client | Optional enrichment is planned and requires explicit consent, minimization, allowlists, rate limits and cache policy |
| Rule supply chain → misleading alerts | Versioned local YAML, unsupported syntax fails at startup, per-rule tests | Rules are trusted deployment inputs, not sandboxed user plugins |
| Dependency/image supply chain | Versioned Python/npm locks, vulnerability scans, CI | Base images/actions use version tags, not digest/SHA pins; clean scans do not prove safety |

## Trust and retention decisions

Raw and normalized telemetry, notes and reports may contain sensitive data. There is no built-in redaction, automatic retention or deletion API. The operator controls filesystem/volume access and must define a retention policy before real collection. Local mode is intended for this synthetic demonstration on a trusted computer. Authenticated mode should receive a TLS proxy, OIDC/MFA, signed collectors, least-privilege DB roles, backups, external audit and load testing before wider deployment.

MITRE updates are an explicit command to one fixed HTTPS source; they send no telemetry. VirusTotal/AbuseIPDB are not wired. No hidden network enrichment occurs during ingestion, investigation or IOC lookup.
