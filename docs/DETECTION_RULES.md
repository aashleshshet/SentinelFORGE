# Detection rules

All rules are **experimental** and validated on synthetic positive/negative fixtures. Confidence is a human-authored triage score. A signal establishes only that the documented predicate matched, not that a host is compromised.

| Rule file | Exact implemented behavior | Severity / confidence | Important false positives / gaps |
|---|---|---|---|
| `ssh-brute-force.yml` | At least 5 SSH failures, same host/IP, within 300 event-time seconds | High / 85 | Shared NAT and stale automation credentials; distributed low-rate guessing is outside scope |
| `powershell-encoded.yml` | PowerShell/pwsh process plus encoded-command, FromBase64String or DownloadString marker | High / 75 | Authorized encoded scripts; unmonitored argument forms, renamed binaries and file-based execution are missed |
| `shell-unusual.yml` | sh/bash/zsh executable plus `/dev/tcp/` in command line | High / 80 | Network diagnostics; Python/netcat/other shell techniques are outside scope |
| `scheduled-task.yml` | `schtasks.exe` with `/create` in command line | Medium / 65 | Installers and legitimate scheduled work; API/COM/PowerShell task creation is not covered |
| `account-uid-zero.yml` | `useradd` plus `-u 0` or `--uid 0` substring | Critical / 90 | Recovery/lab admin; substring matching can also match longer UID strings beginning with zero; no proof of successful creation |
| `sudo-shell.yml` | Auth-log sudo entry targets root and command contains a supported shell path | Medium / 60 | Ordinary administration; does not model authorization baselines or prove an exploit |
| `outbound-port.yml` | Network event to globally routable IP on port 1337, 4444 or 31337 | Medium / 45 | Approved nonstandard services; ports do not prove C2, and ordinary-port C2 is missed |

## Sigma compatibility boundary

Rules use Sigma metadata (`title`, UUID `id`, `status`, `description`, `logsource`, `detection`, `level`, `tags`, `falsepositives`). They target a **custom normalized taxonomy**, `product: sentinelforge`, not arbitrary native Sigma field names. `x-sentinelforge` holds confidence, required telemetry, validation evidence, explanation and optional custom aggregation.

Implemented: nonempty dictionary selections; AND across fields; OR across list values; exact case-insensitive matching; `*`/`?` wildcards on plain strings; literal `contains`, `startswith`, `endswith`; `all` over lists; null comparison; boolean `and`, `or`, `not`, parentheses and named selection references. `fields.*` resolves normalized extension values. Null checks distinguish absent values from strings. No Python evaluation is used.

Not implemented: full pySigma pipelines/backends, native field mappings, regular expressions, CIDR/base64 transforms, Sigma wildcard escaping, selection lists, keyword searches, `1 of`/`all of` selection patterns, Sigma correlation documents, field references, arbitrary numeric aggregation or filters. Unsupported conditions/modifiers fail at rule load instead of being partially ignored. Logsource identifies this normalized taxonomy; event selectors explicitly constrain event kind and fields.

The SSH rule's extension is exactly `{count: 5, seconds: 300, group_by: [host, src_ip]}`. Other aggregations fail at load. Events in the surrounding ±300 seconds are checked for a valid five-minute cluster containing the incoming event, so late arrivals work. Related evidence extends an existing alert in the suppression interval.

## Validation workflow

1. Edit the rule source in `scripts/build_fixtures.py`, including telemetry and false-positive rationale.
2. Run `python scripts/build_fixtures.py` to regenerate seven YAML files and labeled JSON data.
3. Run `pytest tests/test_pipeline.py tests/test_rules.py tests/test_adapters.py`.
4. Run `python scripts/evaluate.py` and inspect both false positives and false negatives.
5. Review `docs/ATTACK_COVERAGE.md` against the narrow predicate, not the rule's title.

Each rule has a positive and benign near-match fixture. Tests assert its ID, ATT&CK mapping, evidence IDs and emitted count. Threshold tests additionally cover out-of-order events, suppression, time windows and distinct source IPs. Overall evaluation intentionally overlaps rule development and is not a held-out efficacy study.
