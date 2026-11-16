# Version 2 synthetic context corpus

These are new experiments with additional observations and separately supplied operator context. They do not replace, relabel or retroactively repair the 18-case legacy dataset. The original `data/evaluation.json` is preserved, along with its contradictory identical-input pairs and historical measurements.

The corpus was authored during detector implementation. The allocation was chosen before target results: 24 development cases (12 positive, 12 negative), 16 validation cases (8/8), and 16 held-out cases (8/8). Four additional malformed-input robustness cases (2/2 assigned intent) are reported separately. Every efficacy partition therefore has an artificial 50% suspicious prevalence. No sample-size or prevalence claim is made about real traffic. The size supports regression coverage; it cannot establish a low population false-positive rate.

## Provenance and labels

All records are hand-authored synthetic observations. No production telemetry, third-party corpus, live malware, network requests or executed commands were used. Scenario reasons state the assigned intent and the available evidence. Some malicious scenarios intentionally lack observable evidence; some benign administration and security-lab cases intentionally satisfy risky predicates. They remain in the corpus regardless of measured outcome.

Each case distinguishes three inputs:

- `events` are submitted sensor observations, including explicitly untrusted extensions. The labels, scenario IDs, intent explanations, expected rules and partition metadata are never submitted to the detector.
- `context` contains operator configuration applied through authenticated administrative APIs. Bindings connect the configured ingestion identity to a source/sensor/host. Approvals scope an exact command digest, observed identity and time window. They are not inferred from an event's `approved=true` field or from a friendly process/path name.
- Intelligence entries have explicit synthetic provenance, version and lifecycle timestamps. The IP literals are inert test strings and do not assert that an actual public resolver or address is malicious. Script digests identify inert synthetic fixture content; they are not malware reputation acquired from a third party.

`expected_rule_ids` describes the supported rule contract, independently of the suspicious/benign label. For example, an assigned malicious HTTPS action without trustworthy enrichment has no expected rule, but its no-alert result remains a binary false negative. A known risky benign admin operation may have an expected alert while remaining a binary false positive. Per-rule correctness must not be mistaken for overall efficacy.

## Partitioning and coverage

The partitions use separate origin-template names, hosts, session IDs and event dates. Selection is by whole scenario, not random rows. Each scenario gets a fresh database. Replay and out-of-order observations remain together inside that scenario. Development covers approval context, malicious and benign script execution, bound HTTPS evidence, forged annotations, unknown content, routine administration, developer tools and network lab activity. Validation and held-out partitions add argument, context lifecycle, identity, command, timestamp and attribution variations. Difficult misses and near-matches were chosen before target results and were not removed to reach a percentage.

The four robustness cases contain an ambiguous timestamp, malformed Sysmon shape, invalid IP address and unknown normalized field. They should be rejected. Their evaluation must report ingestion errors, retain all four scenarios in the input denominator and fail integrity; it must not convert rejection into a benign prediction or silently exclude it from an efficacy run. They are separate because malformed input is a data-quality contract, not evidence of clean detection efficacy.

## Freeze and limitations

`data/evaluation-v2/manifest.json` records the actual freeze timestamp, baseline revision and SHA-256 digest of each partition. The initial held-out hash is `dfb89ba946b305c65d1117ab9ee9900340b94e02da3ebf7cd0446ad5c588b7ff`. Corpus allocation and inputs were frozen before target-result inspection. Detector implementation and corpus authorship overlapped in time; the final parser was being implemented when the freeze message was delivered. This is not an independently designed or blinded external holdout. Labels and expected rules were not informed by its measured results.

The leakage check reports exact structure after removing attribution/clock bookkeeping, shared template/session/host identifiers, and candidate near matches using token-bigram Jaccard similarity at 0.80. It finds no cross-partition exact-structure or identifier collisions. It retains one near candidate: the validation SSH threshold boundary cluster and held-out SSH just-outside-window case (similarity 0.84). Both originate from the same broad SSH threshold rule family despite distinct scenario-template IDs. This overlap disqualifies a claim of independent template-level validation for that family. It is disclosed rather than resolved by deleting a difficult example or renaming a template. The heuristic is a screening aid, not proof of semantic independence; common rule families and author knowledge create additional correlation.

The manifest designates `holdout.json` as the point-estimate acceptance dataset, subject to these provenance limitations. Do not interpret a passing synthetic gate as representative efficacy or population FPR below 5%. Two-sided uncertainty intervals belong beside point estimates; correlated generated cases do not become independent observations because they have different filenames or IDs.

If examining held-out results informs any detector change, retire this partition as development evidence and freeze a new, separately versioned experiment before further acceptance claims. Never rewrite the frozen files, relabel failures, remove hard cases or pad easy negatives. A draft PR can truthfully report unmet targets and exact remaining failures without passing the target gate.

## Frozen annotation limitations

A subsequent source review, without evaluating held-out detection outcomes, identified two design assumptions in the frozen annotations that differ from the implemented contracts. Some command examples put `-ExecutionPolicy` or `-WindowStyle` after `-File`. PowerShell treats tokens after the file target as script arguments; those tokens alone must not count as interpreter policy-bypass or hidden-window options. The development document-child example therefore lacks the specific engine-option conjunction asserted by its expected-rule annotation. The parser should preserve that distinction instead of matching a substring to improve this experiment's score.

Some boundary-case reasons and expected-rule annotations assumed an inclusive context end time. The context service instead defines action/intelligence windows as `[valid_from, valid_until)`, so an event exactly at `valid_until` is outside the window. Frozen annotations remain unchanged. Report any resulting rule-contract mismatches as dataset-design limitations separately from the primary assigned-intent confusion matrix. Neither mismatch authorizes changing a secure implementation contract merely to fit the dataset. A corrected annotation experiment requires a new version and a transparent retirement record; it cannot be presented as repaired original holdout evidence.

## Reproducibility

```sh
python scripts/build_evaluation_corpus.py --check
pytest tests/test_corpus.py
python scripts/evaluate.py --dataset data/evaluation-v2/development.json --output /tmp/development.json
python scripts/evaluate.py --dataset data/evaluation-v2/validation.json --output /tmp/validation.json
python scripts/evaluate.py --dataset data/evaluation-v2/holdout.json --require-targets --output /tmp/holdout.json
python scripts/evaluate.py --dataset data/evaluation-v2/robustness.json --output /tmp/robustness.json
```

The last command is expected to exit unsuccessfully while preserving the rejection report. The target command also writes its report before reporting a failed target. The builder refuses to overwrite frozen data. `--check` verifies generated bytes, manifest hashes and the published leakage report; it does not update the freeze timestamp or inspect detection outcomes.
