# Evidence-led detection improvement — 2026-11-16

The candidate improves the expanded synthetic experiments but **does not meet the requested targets**. The acceptance command exits 1. This is a draft change, not merged into the default branch or promoted to production.

## Baseline and reproducibility

Baseline revision: `78b7bd5c7e17f95993772204d7eaf66a6eec424f`. Candidate detector frozen at `e0f0901` before validation/held-out results were inspected. The initial baseline suite passed 61 tests with 94.92% coverage. Baseline evaluation, fresh benchmark, commands, exit codes, environment and dataset/rule hashes are preserved under [baseline evidence](evidence/detection-improvement/baseline/). The original historical `evaluation-results.json` and `benchmark-results.json` are unchanged. The original 18 inputs and labels remain byte-identical in `data/evaluation.json` and `data/evaluation-v2/legacy-v1.json`.

The legacy identical-input audit identifies three contradictory pairs, hence at least three unavoidable errors and an accuracy ceiling of 15/18 (83.33%) for a deterministic detector given those inputs and identical state. The actual result remains 7 TP, 2 FP, 7 TN and 2 FN. Labels, scenario names, paths, ordering between scenarios and expected rule IDs never enter detector requests.

[Candidate reports and archived-code comparisons](evidence/detection-improvement/candidate/) include exact commands, exit status, class counts, unrounded metrics, source/config/dataset hashes, observed and expected rules, alert/evidence IDs, suppression accounting and errors. Artifact generation can make the Git working-tree flag dirty; source-file hashes identify the executed code. `scripts/compare_baseline.py` archives the original Git revision and runs its real backend in a subprocess. That historical backend has no operator-context API: the reference comparison explicitly supplies only the frozen event observations. It is a capability comparison, not an assertion that both versions consumed context they could not support.

## Measured matrices

Classification unit: one scenario; any emitted alert predicts suspicious. All efficacy scenarios ingest successfully. Per-rule correctness is reported separately and does not redefine the intent label.

| Dataset | Detector | TP / FP / TN / FN | Precision | Recall | Accuracy | FPR |
|---|---|---|---:|---:|---:|---:|
| legacy | reference | 7 / 2 / 7 / 2 | 77.78% | 77.78% | 77.78% | 22.22% |
| legacy | candidate | 7 / 2 / 7 / 2 | 77.78% | 77.78% | 77.78% | 22.22% |
| development | reference | 7 / 4 / 8 / 5 | 63.64% | 58.33% | 62.50% | 33.33% |
| development | candidate | 10 / 1 / 11 / 2 | 90.91% | 83.33% | 87.50% | 8.33% |
| validation | reference | 4 / 1 / 7 / 4 | 80.00% | 50.00% | 68.75% | 12.50% |
| validation | candidate | 6 / 0 / 8 / 2 | 100.00% | 75.00% | 87.50% | 0.00% |
| holdout | reference | 3 / 2 / 6 / 5 | 60.00% | 37.50% | 56.25% | 25.00% |
| holdout | candidate | 5 / 1 / 7 / 3 | 83.33% | 62.50% | 75.00% | 12.50% |

Targets use unrounded values: precision, recall and accuracy strictly >90%; FPR strictly <5%. None of these datasets passes all four. The frozen acceptance set has eight positive and eight negative scenarios. Four malformed-input robustness scenarios remain in their denominators and fail integrity with exit 2; their primary metrics are null, never benign predictions. Undefined metric denominators are also null.

## Scope and uncertainty

The [corpus record](EVALUATION_CORPUS.md) describes the prespecified 24/16/16 development/validation/holdout allocation, artificial 50% prevalence, four separate malformed cases, hashes and provenance. Inputs are synthetic and co-designed during implementation. A retained SSH-family near match crosses validation/holdout (similarity 0.84), and authorship overlaps. These are not independent deployment observations. No external telemetry or real reputation service was used.

Nominal two-sided 95% Wilson score intervals for the 16-case holdout:

- Precision: 43.65%–96.99% (5/6).
- Recall: 30.57%–86.32% (5/8).
- Accuracy: 50.50%–89.82% (12/16).
- False Positive Rate: 2.24%–47.09% (1/8).

These binomial calculations are descriptive sensitivity information under independence assumptions, not evidence that correlated templates form a population sample. Even validation's 0/8 false positives does not establish population FPR below 5%. Point-estimate acceptance is separate from uncertainty. Formula: [NIST Wilson interval reference](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm).

## Actual detection and context changes

- Administrator-only APIs enroll a configured ingestion identity to a source/sensor/host and issue single-use action approvals scoped to user, existing encoded-PowerShell/task rule ID, exact command SHA-256, a <=24-hour event-time window, expiration and reason. Reposting the same action/window conflicts. Event flags, names and paths do not grant approval. Expired/revoked/mismatched context is inert. Suppression preserves the original event and full approval/binding snapshot in audit.
- Two additional rules bring the active count to nine. PowerShell file execution requires either an observed script path/hash matched to active scoped intelligence, or Office ancestry plus a bypass/hidden engine option before `-File`. Renamed executables can use the observed Sysmon/Wazuh original filename. The bounded parser handles supported case/quoting/abbreviations, never executes code, and hashes valid decoded UTF-16LE evidence rather than running it. Script hashes are currently a synthetic-adapter extension; Sysmon executable hashes are never mistaken for script hashes.
- Port 443 alone never triggers the new rule. An authenticated bound collector must observe an exact destination covered by an active, versioned, provenance-bearing administrator-managed IP indicator. No fixture IP is hard-coded in detection. No automatic fetch or third-party disclosure occurs. This is an IP intelligence association; the adapter does not prove TLS/HTTPS content or a C2 session.
- The UID-zero rule now parses exact numeric UID options instead of matching the prefix of UID `0001`. A development regression exposed this documented false-positive behavior. Quoted comments and missing values are covered.
- A security regression preserves event deduplication while allowing a newly bound principal's first redelivery to evaluate the two contextual rules. An earlier unbound sender cannot preempt trusted enrichment by submitting the same event first. Evaluation receipts and audits prevent repeated contextual alerts. Existing alerts are not retroactively erased, and duplicate redelivery never consumes a new suppression grant.
- Rule extensions reject malformed confidence, unknown keys, missing required metadata and invalid aggregation. Source definitions and generated YAML are checked for drift. The public snapshot remains synthetic and read-only, with 18 events, seven alerts and two cases; it exposes nine rule definitions.

These controls verify administrator authorization and authenticated collector scope. They do not cryptographically attest a physical host, user identity or script bytes; a compromised enrolled collector and a malicious administrator remain trusted-boundary risks. Approval is an exact action decision, not an account-wide allowlist. Existing static token, local loopback, two-person response simulation and API authorization boundaries remain in place.

## Exact remaining errors

| Dataset | Scenario | Outcome | Frozen labeling rationale |
|---|---|---|---|
| legacy | `authorized-encoded-admin` | FP | Authorized encoded PowerShell produces a known false positive |
| legacy | `authorized-task-maintenance` | FP | Approved task creation produces a known false positive |
| legacy | `powershell-file-evasion` | FN | Malicious file execution without monitored arguments is outside coverage |
| legacy | `https-c2-blindspot` | FN | HTTPS C2 is not detected by the uncommon-port heuristic |
| development | `development-document-child-file-bypass` | FN | Synthetic malicious document launches file execution with policy bypass |
| development | `development-unobserved-file-content-gap` | FN | Assigned malicious script content is not observed; detection should retain this known context gap |
| development | `development-benign-admin-without-approval` | FP | Assigned authorized administration intentionally lacks independently supplied approval; a known ambiguity retained |
| validation | `validation-renamed-presentation-child` | FN | Sensor-observed original filename identifies renamed PowerShell with suspicious parent and bypass |
| validation | `validation-expired-network-intelligence-gap` | FN | Assigned malicious destination has expired intelligence; no current trustworthy evidence should trigger |
| holdout | `holdout-spreadsheet-file-short-switch` | FN | Spreadsheet child launches a quoted file through the short file option with bypass |
| holdout | `holdout-indicator-inclusive-event-end` | FN | Current synthetic IP evidence is valid at the event-time window end |
| holdout | `holdout-unobserved-https-command-channel` | FN | Assigned malicious HTTPS intent without threat intelligence or behavioral proof remains an observable-context gap |
| holdout | `holdout-approved-action-end-window` | FP | Exact administrative action is valid at the approval event-time window end |

The frozen corpus contains annotation mistakes that remain visible in contract reporting: some engine options appear after `-File` and are therefore script arguments; timestamp-end annotations assumed inclusive windows, whereas context uses explicit half-open `[valid_from, valid_until)` windows. These failures are not deleted or relabeled. Microsoft documents that parameters following `-File` belong to the script: [PowerShell command-line reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1). Future corrected experiments must be separately versioned; no further detector tuning was performed against these held-out results.

## Measured cost

Same development host/runtime and 1,000-event benign workload, three runs: fresh baseline median **6,380.11 events/s** with seven rules; candidate median **3,025.10 events/s** with nine rules. This is a **52.6% throughput reduction**, not an improvement. Per-event enrollment checks and receipt handling add database work. Neither run has populated bindings/indicators, so this does not quantify populated-feed lookup cost.

The separately measured candidate alert-heavy workload emitted 1,000 alerts into 100 cases: median **999.72 events/s** across three runs. No comparable historical alert-heavy claim is made. Measurements include in-process HTTP validation, normalization, detection and commit; they exclude sensor/network delay and are not detection delay or MTTD. Historical 6,072.36 events/s remains an older observation, not reused as a new result.

## Validation and release posture

Local validation passes: 159 Python tests, 95.32% coverage (85% gate), five authenticated browser tests and six public/guide/accessibility tests. TypeScript/Vite, Ruff, Prettier, locked dependency audits and deterministic generation checks pass. The CI console-entry-point import issue was fixed by adding the repository root to pytest's import path; this changes test discovery only, not the frozen detector. PostgreSQL and final CI results are recorded in the PR. New tests cover metric boundaries/nulls/errors, contradictory inputs, report-before-failure, corpus hashes/leakage, context RBAC/expiry/replay/forgery/concurrency/rollback, script evidence, ordinary HTTPS and deduplication. Existing SSH thresholds, correlation, adapters, evidence and public isolation remain covered.

CI keeps backend/PostgreSQL, browser and Docker Compose checks and adds a separate **blocking `detection-targets` job** for the manifest-designated holdout. It publishes the failing raw report with `if: always()`; it does not lower thresholds, suppress the target failure or apply the impossible legacy target as a release criterion. The legacy target failure is separately checked as an expected informative result.

Remaining work: obtain independently authored/authorized deployment evidence, correct corpus annotation defects in a new version, expand observed script/network context, review collector attestation, and reduce context-query cost without weakening provenance. A new holdout is required before tuning based on these results. No >90%/<5% efficacy claim or production-readiness claim is made.
