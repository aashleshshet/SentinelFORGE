# Validation evidence

Candidate detector: `e0f0901`. Subsequent `c85c671` changes only pytest's import path so `pytest` and `python -m pytest` both discover evaluator tests. The locked Python 3.12.14 environment was installed with `python -m pip install -r requirements.lock` and `python -m pip install --no-deps -e .`; both exited 0. Original baseline commands, exit codes and environment are in `../baseline/provenance.json`.

| Command/check | Exit/result |
|---|---|
| `pytest --cov=sentinelforge --cov-fail-under=85 --cov-report=xml` | 0; 159 passed, coverage 95.32%; full log retained |
| `ruff check backend tests scripts` | 0 |
| `ruff format --check backend tests scripts` | 0; 38 files |
| `pnpm --dir frontend run build` | 0; TypeScript and Vite |
| Prettier check on changed TSX and all e2e TS | 0 |
| `SF_BASE_URL=http://127.0.0.1:8001 playwright test` | 0; five authenticated tests passed in 7.1s; six public-only tests skipped here and run below |
| `SF_PUBLIC_DEMO=1 SF_BASE_URL=http://127.0.0.1:8002 playwright test public-demo.spec.ts modernization.spec.ts` | 0; six passed in 19.4s |
| `python scripts/build_evaluation_corpus.py --check` | 0; all frozen hashes/regeneration/leakage checks match |
| `python scripts/build_fixtures.py` then Git diff of rules/original data | 0; no drift |
| `python scripts/build_public_demo.py --check` | 0; exact deterministic snapshot |
| `pip-audit -r requirements.lock` | 0; no known vulnerabilities |
| `pnpm --dir frontend audit --audit-level high` | 0; no known vulnerabilities |

The tests used isolated SQLite and synthetic local servers, never the user's editable database. Docker/PostgreSQL verification is run on GitHub's Linux runner because Docker is not installed locally. CI links and final status are recorded in the PR. Node color-environment and Starlette TestClient/httpx deprecation warnings remain non-failing and unsuppressed.

The `*-red.log` files preserve initial failing regressions before their corresponding implementation changes. Those failures are expected development evidence, not final validation failures. Candidate evaluation/benchmark commands, exit statuses and raw outputs are under `../candidate/`; failed target exits and malformed-input failures remain published.
