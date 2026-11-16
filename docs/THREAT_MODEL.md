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

## Detection context additions

Administrator enrollment binds a preconfigured ingestion identity to a source/sensor/host, with expiration and reason. Suppression additionally binds observed user, exact command digest, one of two approvable rules, bounded event-time window and one use. Only the actual authenticated principal can match the enrollment; event claims cannot grant an exemption. Writes and approval consumption use the existing serialized transaction boundary, including PostgreSQL advisory locking. Duplicate approval requests cannot extend a consumed grant. Suppression and enrichment retain immutable-by-API context snapshots/digests in audit; a database administrator can still alter them.

This is operator-verified enrollment, **not cryptographic sensor or human identity attestation**. An enrolled collector can lie within its assigned scope; a privileged administrator can import misleading intelligence or authorize a malicious exact action. Narrow actions, short windows, expiry, provenance and audit reduce ambiguity but cannot remove that trust. Reason/provenance text is not independently authenticated. Static bearer-token and shared-loopback limitations remain.

An unbound sender's earlier copy cannot block a bound collector's first contextual evaluation: redelivery preserves event deduplication and records a per-principal context receipt. Existing alerts are not erased. Later indicator updates do not trigger automatic historical reanalysis; that is a documented coverage limit.

Four additive tables (`collector_bindings`, `detection_approvals`, `threat_indicators`, `context_receipts`) are created by the existing startup schema setup. No existing column is rewritten. Back up local databases before adopting schema changes; production migration/rollback orchestration remains outside this lab. The public snapshot contains empty context tables and the public middleware rejects every context mutation before body processing.
