# Command evidence accuracy upgrade — 2026-11-16

The new parser corrects 21 false alerts across the frozen 120-case v3 synthetic challenge, with no new classification errors. On its 40-case holdout, assigned-intent accuracy improves **70.0% → 87.5%**, precision **64.29% → 85.71%**, and FPR **50.0% → 15.0%**; recall stays **90.0%**. All 40 holdout rule contracts match. **The strict >90% precision/recall/accuracy and <5% FPR targets remain unmet.** Contract correctness is distinct from recognizing malicious intent.

These are deliberately difficult, correlated, engineer-authored command examples at artificial 50% prevalence. They are not representative operational measurements or an independent blinded efficacy study. The original acceptance gate remains unchanged and failing. The user subsequently authorized production deployment of the public synthetic demo; the verified release is recorded below. The draft branch remains unmerged into `main`.

## Implementation

- PowerShell engine options consume their values instead of scanning those values as switches. Supported option prefixes, native switch introducers and empty quoted arguments preserve token positions. `pwsh` positional file arguments and explicit `-File` terminate engine parsing. `-CommandWithArgs` examines its command argument separately from subsequent literal arguments. Effective repeated policy/window options replace earlier values. Unknown options and unsupported syntax stop interpretation.
- Scheduled-task detection matches the exact `/create` operation on the observed `schtasks.exe` process. A task name, action argument or `/createish` substring cannot supply the operation.
- UID-zero detection uses bounded getopt-style parsing: short clusters, attached values, consumed non-UID values, `--`, and the final valid UID selection. Linux executable identity is case-sensitive.
- Sudo detection checks an exact supported shell executable under `/bin` or `/usr/bin`, rather than a substring anywhere in the command. Denied and unrecognized policy logs remain failure/unknown. The rule title and explanation distinguish an authorization grant from process completion and interactivity.
- New action flags are computed in the temporary matching view and overwrite telemetry-supplied flags there. Raw events are retained. No submitted command, decoded program or script is executed. Nine rule IDs and the original fixtures remain intact.

The [rule reference](DETECTION_RULES.md) links the primary command/parser documentation. These are bounded observation parsers, not native interpreters: aliases, environment expansion, wrappers, symlinks and all Windows escaping forms are not modeled. Valid-looking syntax does not prove successful execution or malicious intent.

## Frozen experiment and results

Baseline: `88bcda800bb877cd1e354301e7b727953157d962`. Candidate: `93f7d490cea1ac65f30e50f5c4bea88a8e8a3cad`. Both were evaluated from clean trees with the same dataset hashes and `2026-11-16T12:00:00Z` processing clock, using the full API/context path. The reference checkout uses its own backend, rules and evaluator. Source/configuration/dependency hashes are recorded in every raw result.

The separate authoring agent wrote the [plan](EVALUATION_V3.md) and builder without running the detector or inspecting candidate edits. Its tool turn ended before generation; the root agent formatted and ran the builder without opening its scenario definitions. All three splits were frozen before any v3 evaluation. The code and corpus were committed together before development, validation and then holdout runs. No runtime changes or candidate selection followed any v3 results. Each split was evaluated once per version; the candidate holdout used `--require-targets` and exited **1**, correctly recording failure after writing its report.

| Split (20 positive / 20 negative each) | Matrix TP/FP/TN/FN, before → after | Precision | Recall | Accuracy | FPR | Rule contracts |
| --- | --- | --- | --- | --- | --- | --- |
| Development | 18/11/9/2 → 18/3/17/2 | 62.07% → 85.71% | 90% → 90% | 67.5% → 87.5% | 55% → 15% | 32/40 → 40/40 |
| Validation | 18/9/11/2 → 18/3/17/2 | 66.67% → 85.71% | 90% → 90% | 72.5% → 87.5% | 45% → 15% | 34/40 → 40/40 |
| Holdout | 18/10/10/2 → 18/3/17/2 | 64.29% → 85.71% | 90% → 90% | 70% → 87.5% | 50% → 15% | 33/40 → 40/40 |

All 120 scenarios ingested with no errors or rejections in each version. Across the partitions, 21 former false positives become true negatives; no true positive or true negative regresses. Recall gains for additional supported CLI forms are demonstrated by source-led unit regressions, not by this corpus, whose positive cases already matched the baseline. Do not claim a measured recall improvement.

F1, calculated as `2TP / (2TP + FP + FN)`, improves from 73.47% to 87.80% on development, 76.60% to 87.80% on validation, and 75.00% to 87.80% on holdout. The paired comparison records these derived values separately from the unchanged evaluator reports.

The holdout SHA-256 is `220550ffc936c8bef10ebb56d6517a38102914815bd934f8ff7894454bfd4c7d`. [Manifest](../data/evaluation-v3/manifest.json), [paired comparison](evidence/accuracy-upgrade/comparison.json), [baseline artifacts](evidence/accuracy-upgrade/baseline/) and [candidate artifacts](evidence/accuracy-upgrade/candidate/) preserve exact inputs, outcomes and provenance. These inspected cases now serve as regression evidence; future tuning on them requires a separately versioned holdout for any new acceptance claim.

Nominal two-sided 95% Wilson intervals on the candidate holdout are precision 65.36–95.02%, recall 69.90–97.21%, accuracy 73.89–94.54% and FPR 5.24–36.04%. Correlated synthetic variants violate an independent population-sampling interpretation; these intervals do not establish field efficacy.

## Remaining errors and historical regressions

The five holdout intent errors were deliberately retained in the prespecified plan:

| Scenario suffix | Result | Why it remains |
| --- | --- | --- |
| `plain-command-intent` | FN | Malicious intent is assigned without a supported observable suspicious predicate. |
| `file-content-intent` | FN | File content is not observed and no applicable contextual evidence identifies it. |
| `authorized-encoded` | FP | Legitimate encoding meets the predicate; no applicable recorded action approval distinguishes it. |
| `authorized-uid` | FP | Authorized UID-zero administration meets the predicate; the current approval model does not exempt this rule. |
| `authorized-office` | FP | Legitimate Office automation meets the narrow file-context predicate. |

The plan's supported contract therefore permits 35/40 intent-correct classifications per split even at 40/40 contract correctness. Removing these ambiguous examples or suppressing rules by fixture metadata would make the report misleading. Broader gains require additional observable evidence and independently labeled authorized telemetry.

Legacy and every v2 scenario retain their exact prior classifications: legacy 7/2/7/2, v2 development 10/1/11/2, validation 6/0/8/2 and holdout 5/1/7/3. Original inputs, labels, frozen plans and historical evidence are unchanged. The v2 holdout remains 75% accurate, and its strict CI gate stays blocking. All four malformed robustness inputs remain errors, with null primary metrics and exit **2**. Their errors are not counted as benign predictions.

## Verification and compatibility

260 Python tests pass, with 95.71% coverage above the 85% requirement. Ruff lint/format, v2/v3 hash verification, generated rules and public snapshot reproducibility pass. The public synthetic snapshot still contains 18 events, seven alerts, two cases and nine rules. Source-led regressions include forged flags and retained raw evidence, option/value boundaries, denied sudo records and grouped/repeated UID flags.

CI verifies v3 corpus hashes and replays all three inspected partitions as regression tests, requiring their 120 rule contracts to match. This additional engineering check does not replace the original blocking v2 efficacy gate or imply that repeated holdout runs constitute new independent validation.

At application/CI revision `70159ed316445614f32d987cf9ead831c0fa28ea`, [GitHub Actions run 43888601585](https://github.com/aashleshshet/SentinelFORGE/actions/runs/43888601585) passed **backend/PostgreSQL, browser and containers**. Both SQLite and PostgreSQL ran all 260 Python tests; coverage was 95.71%. The v3 replay/contract step passed. Only **detection-targets** failed at the unchanged strict acceptance check, and its raw report was uploaded. Documentation and derived report additions after this revision do not change the frozen candidate runtime or evaluation inputs.

Existing stored events are not reprocessed or rewritten. New sudo normalization adds authorization metadata, so replaying an old raw sudo event after upgrading can yield a different normalized fingerprint; cross-version deduplication is not guaranteed. No schema migration, new dependency or change to authentication, approval scope, context expiry or read-only demo permissions is introduced. This report makes no new throughput claim.

To verify the corpus and replay a candidate:

```sh
python scripts/build_accuracy_corpus.py --check
python scripts/evaluate.py --dataset data/evaluation-v3/development.json --output work/v3/development.json
python scripts/evaluate.py --dataset data/evaluation-v3/validation.json --output work/v3/validation.json
python scripts/evaluate.py --dataset data/evaluation-v3/holdout.json --require-targets --output work/v3/holdout.json
# Expected final exit: 1 (valid evaluation, strict efficacy targets unmet).
```

To reproduce the reference, create a detached checkout at the baseline revision and run its evaluator with `PYTHONPATH=backend`, pointing `--dataset` at the same absolute v3 file and using the locked Python environment. Never use the older `compare_baseline.py` context-free harness for this comparison: this baseline supports the context API and must receive the same operator observations.

## Public production release

At the user's explicit request on 2026-11-16, Vercel rebuilt the exact ready Git preview for source `0aa11033164ca56414f6ef8109ea72f9a964fadc` as production deployment `dpl_HGJEzzBmSNbcuesieaULeWLxXffo`. Project `sentinelforge` (`prj_odyoVI5sZitJkIXGRWuNFgc6J57H`), team `aashlesh-ramadas-shet`. Status **READY**; approximately 48.0 seconds from build start to ready. The [public demo](https://sentinelforge-theta.vercel.app) and [product overview](https://sentinelforge-theta.vercel.app/what-it-is) serve this revision. Previous production `dpl_9iVvPv3GjP2zudLE8pp85rPcuoed` remains available for rollback.

All **10 public browser tests passed in 44.3 seconds** against the canonical production domain; four authenticated-only tests were appropriately skipped. API checks confirmed viewer identity, `demo: true`, `local: false`, the new “Root shell through sudo” rule title and accepted authorization metadata, 18 events/seven alerts/two cases/nine rules, and HTTP 403 for public replay. CSP, nosniff, frame denial and referrer policy were present. The first auxiliary verification script used an incorrect stats key; correcting it to the documented `open_cases` field required no application change, and the complete API check passed.

The deployment-scoped production error/fatal scan returned no matching records in the 2026-11-16 20:09:59–20:24:59 IST window (14:39:59–14:54:59 UTC). No log drains are configured; this is a point-in-time scan, not continuous monitoring. Existing preview protection and environment credentials were unchanged. The hosted app remains a fixed synthetic read-only demo, not a live operator ingestion workspace. No local operational data was uploaded, no PR was merged, and the failing strict detection efficacy gate remains unchanged. Subsequent edits only record this release.
