# Detection rules

All rules are **experimental** and validated on synthetic positive/negative fixtures. Confidence is a human-authored triage score. A signal establishes only that the documented predicate matched, not that a host is compromised.

| Rule file | Exact implemented behavior | Severity / confidence | Important false positives / gaps |
|---|---|---|---|
| `ssh-brute-force.yml` | At least 5 SSH failures, same host/IP, within 300 event-time seconds | High / 85 | Shared NAT and stale automation credentials; distributed low-rate guessing is outside scope |
| `powershell-encoded.yml` | PowerShell identity (image or observed original filename), bounded supported encoded engine option or inline download/decode marker | High / 75 | Authorized encoded scripts; Unsupported quoting/obfuscation can be missed; file context has a separate rule |
| `shell-unusual.yml` | sh/bash/zsh executable plus `/dev/tcp/` in command line | High / 80 | Network diagnostics; Python/netcat/other shell techniques are outside scope |
| `scheduled-task.yml` | `schtasks.exe` with exact `/create` operation before task/action arguments | Medium / 65 | Installers and legitimate scheduled work; observes a request, not registration; API/COM/PowerShell task creation is not covered |
| `account-uid-zero.yml` | Case-sensitive `useradd` executable with effective final zero-valued UID option, including short clusters such as `-ou0` | Critical / 90 | Recovery/lab admin; exact numeric zero only; no proof of successful creation |
| `sudo-shell.yml` | Accepted sudo authorization targets root and the command executable is exactly bash/sh/zsh under `/bin` or `/usr/bin` | Medium / 60 | Ordinary administration; permission grant does not establish execution completion, interactivity or an exploit |
| `outbound-port.yml` | Network event to globally routable IP on port 1337, 4444 or 31337 | Medium / 45 | Approved nonstandard services; ports do not prove C2, and ordinary-port C2 is missed |

| `powershell-file-context.yml` | Supported `-File` or pwsh implicit file plus a bound observed path/hash intelligence match, or Office parent plus effective preceding bypass/hidden option | High / 80 | Security lab or Office automation; absent observations remain misses |
| `https-context.yml` | Bound source, port 443 and exact active versioned operator IP intelligence | High / 80 | Shared hosting or inaccurate intelligence; no TLS/content inspection |

## Sigma compatibility boundary

Rules use Sigma metadata (`title`, UUID `id`, `status`, `description`, `logsource`, `detection`, `level`, `tags`, `falsepositives`). They target a **custom normalized taxonomy**, `product: sentinelforge`, not arbitrary native Sigma field names. `x-sentinelforge` holds confidence, required telemetry, validation evidence, explanation and optional custom aggregation.

Implemented: nonempty dictionary selections; AND across fields; OR across list values; exact case-insensitive matching; `*`/`?` wildcards on plain strings; literal `contains`, `startswith`, `endswith`; `all` over lists; null comparison; boolean `and`, `or`, `not`, parentheses and named selection references. `fields.*` resolves normalized extension values. Null checks distinguish absent values from strings. No Python evaluation is used.

Not implemented: full pySigma pipelines/backends, native field mappings, regular expressions, CIDR/base64 transforms, Sigma wildcard escaping, selection lists, keyword searches, `1 of`/`all of` selection patterns, Sigma correlation documents, field references, arbitrary numeric aggregation or filters. Unsupported conditions/modifiers fail at rule load instead of being partially ignored. Logsource identifies this normalized taxonomy; event selectors explicitly constrain event kind and fields.

The SSH rule's extension is exactly `{count: 5, seconds: 300, group_by: [host, src_ip]}`. Other aggregations fail at load. Events in the surrounding ±300 seconds are checked for a valid five-minute cluster containing the incoming event, so late arrivals work. Related evidence extends an existing alert in the suppression interval.

## Validation workflow

1. Edit the rule source in `scripts/build_fixtures.py`, including telemetry and false-positive rationale.
2. Run `python scripts/build_fixtures.py` to regenerate nine YAML files and labeled JSON data.
3. Run `pytest tests/test_pipeline.py tests/test_rules.py tests/test_adapters.py`.
4. Run `python scripts/evaluate.py` and inspect both false positives and false negatives.
5. Review `docs/ATTACK_COVERAGE.md` against the narrow predicate, not the rule's title.

Each rule has a positive and benign near-match fixture. Tests assert its ID, ATT&CK mapping, evidence IDs and emitted count. Threshold tests additionally cover out-of-order events, suppression, time windows and distinct source IPs. Overall evaluation intentionally overlaps rule development and is not a held-out efficacy study.

## Explicit context and parsing limits

See [context API](API.md#scoped-detection-context), [telemetry provenance](TELEMETRY.md#context-supported-detection-observations) and [measured results](DETECTION_IMPROVEMENT.md). Administrative approvals apply only to encoded-PowerShell/task rules, never to the two new contextual rules or every action by an account. No rule executes submitted commands or decoded content. Encoded arguments are bounded at 8,192 characters; command tokenization at 16,384 characters/256 tokens. Unsupported or truncated quoting does not invent a file evidence match. Parameters after `-File` belong to the script, and context windows exclude their ending timestamp.

The original seven rule fixtures and legacy 18 scenarios remain byte-identical. New context contracts live in `tests/test_context.py` and `tests/test_process_evidence.py`; expanded experiment labels are separate from rule expectations. Rule extension validation fails closed rather than silently accepting exemptions or malformed metadata.

Command-boundary regressions additionally cover consumed engine option values, documented PowerShell prefixes, empty quoted arguments, native `-`/`--`/`/` switches, the `pwsh` implicit-file boundary, effective repeated UID/policy values, task operations inside quoted values, and denied sudo logs. `-CommandWithArgs` inspects only its command argument; remaining arguments are data. Unknown engine options stop analysis instead of allowing later values to masquerade as options. Missing/invalid encoded payloads remain attempted encoded-command signals. Linux executable identity is case-sensitive. No parser resolves aliases, symlinks, environment variables, nested shells or arbitrary Windows quoting/escaping; complete native execution validity is not claimed.

Semantics follow the [PowerShell 7.5.4 parser](https://github.com/PowerShell/PowerShell/blob/v7.5.4/src/Microsoft.PowerShell.ConsoleHost/host/msh/CommandLineParameterParser.cs), [schtasks operation syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks), upstream [useradd getopt parsing](https://github.com/shadow-maint/shadow/blob/master/src/useradd.c) and [sudoers log format](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in). The [v3 challenge plan](EVALUATION_V3.md) separates assigned intent from these narrow rule contracts; it is synthetic engineering evidence, not operational efficacy.
