# Contributing

Use the local setup in README. Work on a branch and open a pull request describing the actual behavior, its evidence, and limitations. Never commit `.env`, tokens, production logs, database files, or user-specific paths.

## Validation

```sh
ruff check backend tests scripts
ruff format --check backend tests scripts
pytest --cov=sentinelforge --cov-fail-under=85
pnpm --dir frontend run build
python scripts/evaluate.py --output /tmp/evaluation.json
```

Run the browser workflow when changing UI/API contracts. PostgreSQL CI runs the same contract suite. Do not overwrite checked-in measured results with CI machine results; upload those as CI artifacts. Update the evaluation documentation when deliberately publishing a new benchmark.

## Detection changes

Every new or changed rule needs a positive fixture, a benign near-match, explicit false-positive assumptions, required telemetry, ATT&CK rationale and a validation status. Keep rules experimental until evidence justifies promotion. A test must assert the actual rule ID and event evidence, not only that some alert exists. Update `scripts/build_fixtures.py` when changing generated rule or fixture definitions, then regenerate and test. Do not silently broaden the supported Sigma grammar.

## Architecture and security

Keep parsing separate from detection and correlation. Never execute event command lines. New external enrichment needs opt-in disclosure policy, public-IOC validation, field minimization, provider allowlists, timeouts, bounded caching and rate/backoff tests. New endpoint response adapters require a separate design/security review; existing simulation endpoints must remain simulation-only. Mutations must take the common writer lock and append an audit entry.

## License

Contributions are MIT licensed, with MITRE ATT&CK and bundled font/library attribution retained. Do not include third-party rules or data without checking their license. Prefer clear code and meaningful behavior tests over claims of broad coverage.
