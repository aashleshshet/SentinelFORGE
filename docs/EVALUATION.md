# Evaluation

The evidence-led candidate and before/after matrices are recorded in [the detection improvement report](DETECTION_IMPROVEMENT.md). Targets remain unmet. Its evaluator adds accuracy, strict gates, null denominators, 95% Wilson intervals, rejection accounting, contradiction and leakage checks. [Corpus provenance](EVALUATION_CORPUS.md) and raw generated reports distinguish each experiment. The historical measurements below remain unchanged.

## Historical baseline

The checked-in results were measured on Python 3.12.14, macOS arm64. Detection classification uses SQLite in memory; throughput uses a fresh SQLite file with WAL for each run. These measurements are evidence for this implementation under the stated workload, not deployment performance guarantees.

## Dataset and unit of analysis

`data/evaluation.json` has 18 labeled scenarios (including three identical-input pairs with opposite labels), nine suspicious and nine benign. Each runs in a fresh database, avoiding contamination between thresholds or suppression windows. Seven suspicious scenarios exercise the seven rule contracts; seven benign near-matches test exclusions. Two additional benign administrative scenarios deliberately trigger alerts; two suspicious scenarios deliberately avoid the monitored predicates. Labels describe the scenario's assigned intent, including cases whose visible telemetry is indistinguishable without context.

Classification is **per scenario**: any emitted alert predicts suspicious. Per-rule contract tests separately assert the correct rule ID, ATT&CK ID and evidence. The fixtures overlap development; this is not an independent holdout, a prevalence-weighted field test or a statistically representative sample.

## Measured classification

| Metric | Actual result |
|---|---:|
| True positives | 7 |
| False positives | 2 |
| True negatives | 7 |
| False negatives | 2 |
| Precision = TP / (TP + FP) | 77.78% |
| Recall = TP / (TP + FN) | 77.78% |
| False-positive rate = FP / (FP + TN) | 22.22% |
| Median ingestion-to-committed-response latency, alerting scenarios | 3.333 ms |
| Maximum latency, alerting scenarios | 9.719 ms |

Latency includes FastAPI TestClient transport, input validation, normalization, DB writes, detection, correlation and commit. It excludes actual network transit, sensor collection time and observation-to-ingest delay. For threshold rules it includes the submitted batch, not the time an attacker takes to produce five failures. It is not an MTTD estimate.

Known false positives: approved encoded PowerShell and scheduled maintenance. Known false negatives: malicious PowerShell file execution without monitored argument markers and C2 over port 443. These failures are retained, not removed to improve the headline metrics. Additional unmeasured gaps include renamed binaries, different shell techniques, spread-out SSH guessing, incomplete auditd assembly and command-line truncation.

## Throughput

`python scripts/benchmark.py --events 1000 --runs 3` measured **6,072.36 events/s median**, with individual results 6,027.88, 6,184.59 and 6,072.36 events/s. Workload: 1,000 distinct benign process events, batches of 100, 100 hosts, seven active rules, one in-process client, one commit per batch, fresh SQLite/WAL database. Median batch latencies were 15.233, 16.041 and 16.377 ms.

This small, warm local benchmark does not measure PostgreSQL, container limits, live ingestion, network overhead, concurrent clients, alert-heavy processing, long-lived threshold history or large-retention searches. Alert/stat queries and SSH lookback scans need further load testing before scale claims.

## Reproduce

```sh
python scripts/build_fixtures.py
pytest tests/test_pipeline.py tests/test_rules.py tests/test_adapters.py
python scripts/evaluate.py --output /tmp/evaluation.json
python scripts/benchmark.py --events 1000 --runs 3 --output /tmp/benchmark.json
```

See [raw evaluation results](evaluation-results.json), [raw benchmark results](benchmark-results.json) and [validation status](VALIDATION.md). Timing varies with hardware and runtime. CI publishes its own measurements as artifacts rather than overwriting these recorded observations.
