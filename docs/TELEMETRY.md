# Telemetry adapters

Every envelope has `source`, `sensor`, `payload`, and optional `host`/`timestamp`. The envelope's source/sensor override any values inside a synthetic payload. The collector is authenticated but the source's claims are not cryptographically verified. See `data/demo.json` and `data/rule-fixtures.json` for complete runnable examples.

| Source | Implemented input | Required context / limits |
|---|---|---|
| `linux_auth` | SSH Failed/Accepted password/publickey or sudo `USER=…; COMMAND=…` text; optionally `{message: text}` | RFC3339 prefix can supply host/time. Traditional yearless syslog needs explicit envelope host and timezone-aware timestamp; no guessed year/zone |
| `auditd` | Assembled SYSCALL + EXECVE text with `audit(epoch:serial)`, `exe`, arguments; or parsed JSON with `exe`, `command`, uid/euid/auid | Envelope host or JSON node required. Assembly of multi-record events is upstream. Hex-encoded audit arguments, PROCTITLE decoding and syscall-only argument reconstruction are not implemented |
| `sysmon` | JSON `Event.System` / `Event.EventData`, or flat exported JSON | Event IDs 1 (process) and 3 (network). Sysmon `UtcTime` is explicitly UTC. XML/EVTX ingestion and other IDs are rejected |
| `wazuh` | Native alert JSON with `agent.name` and timestamp | SSH/sudo full_log with recognized decoder; Windows Sysmon `data.win` mapped to same adapters. Other alerts are stored as `other`, not treated as proven detections |
| `zeek` | `conn.log` JSON with `ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, uid/proto/service | Host must be assigned by the collector. TSV logs, DNS/HTTP records and IP-to-host inventory mapping are not implemented |
| `synthetic` | JSON object using the normalized schema | Explicit host and timezone-aware timestamp. Unknown top-level normalized fields rejected; extensions go under `fields` |

## Normalization decisions

UTC is required; naive non-Sysmon timestamps are rejected. Epoch values are accepted where the adapter defines them. IP addresses and ports are validated. Blank host names are rejected. Original JSON/text is retained separately. Casefolded host/user names enable consistent correlation, but v0.1 does not resolve usernames across directory domains or numeric Linux IDs to names.

Exact-replay fingerprint = SHA-256 of canonical JSON containing normalized data plus the original payload. Receipt time is excluded. Sensor attribution is included through the normalized data. Equivalent records with different raw encodings are not automatically merged; this conservatively retains evidence. Events lacking unique upstream IDs can still be indistinguishable if their timestamp and content are identical. No cross-sensor semantic deduplication is claimed.

Parser failures are returned per event; bodies and tokens are not copied into logs. Rejected raw payloads are not saved to a dead-letter store. Transport retries can safely resend identical content. A sender still needs to persist unacknowledged batches for durable delivery.

## Live collection

The platform provides an authenticated batch boundary and a replay client. It does not install agents, open network listeners for Syslog, tail files, or control Wazuh. Configure your collectors to export the accepted JSON envelopes, assemble auditd records, attribute network hosts, and submit batches. Those deployment-specific collector integrations are planned work, not simulated as active services in the dashboard.

## Context-supported detection observations

Sysmon Event ID 1 and its Wazuh mapping preserve `OriginalFileName` as `fields.original_file_name`. This can identify renamed PowerShell binaries but remains a collector observation, not signed executable verification. `ParentImage` supplies the immediate parent; ancestry beyond that is not collected.

A synthetic normalized process can supply `fields.script_path` and a 64-hex `fields.script_sha256`. To support a script-intelligence signal, the observed path must lexically match the supported `-File` argument and the hash must match active administrator-managed intelligence. The collector must have a matching authenticated principal/source/sensor/host binding. These fields are synthetic adapter extensions until a real content-observing sensor integration exists. Sysmon's process `Hashes` identifies the interpreter image and is deliberately not mapped to a script hash. Neither a literal filename nor `approved=true` is a reputation verdict.

The two new rules and UID parsing use server-computed matching flags. Caller-provided `fields.sf_powershell_encoded`, `sf_powershell_file_suspicious`, `sf_https_indicator` and `sf_uid_zero` are overwritten in a temporary matching copy. Original raw/normalized evidence is preserved. Enrollment and intelligence are separately audited operator configuration, not event labels or synthetic intent annotations.

Network telemetry provides destination IP/port. Port 443 does not prove TLS, HTTPS or maliciousness. The context rule is an exact, active offline intelligence association from an enrolled source; missing/revoked/expired context produces no new intelligence alert. There is no TLS decryption, DNS correlation, beacon detector or live external reputation fetch.

Exact content fingerprinting is unchanged. See [context redelivery behavior](API.md#scoped-detection-context) for the separately audited evaluation of a bound principal's first duplicate delivery after an unbound source. No duplicate event or ordinary alert is fabricated.
