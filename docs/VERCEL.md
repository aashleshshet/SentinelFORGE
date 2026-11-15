# Public portfolio deployment

The Vercel project serves a public, read-only synthetic demonstration. No sign-in, API token, cloud database or external enrichment service is required. The native local launcher remains the full editable workspace.

## Data and isolation

`scripts/build_public_demo.py` replays `data/demo.json` through the actual authenticated ingestion API in an isolated in-memory database. It runs the seven detection rules, creates correlated cases, adds clearly synthetic investigation notes and preserves evidence snapshots. The result is committed as `data/public-demo.json` with a digest of its source fixtures and rules. IDs and bookkeeping timestamps are deterministic.

The dedicated `app.py` entrypoint ignores operator credentials, database URLs and file paths. Each function instance loads the same bundled snapshot into an in-memory SQLite database, then enables SQLite's query-only mode. All mutations are rejected before processing their body. Public visitors can query/filter telemetry, alerts, cases and rules, inspect timelines, and download preserved synthetic reports. Evidence exports verify their digest but do not append audit rows in the immutable demo. Other analyst/admin operations remain inaccessible.

This deliberately holds no mutable state between serverless invocations. A request reaching a different instance sees the same IDs and data. Public mode is not an editable SOC deployment, a live sensor feed or a place to upload telemetry. Its in-process request limiter is per instance, not a distributed abuse-control system.

## Deployment

Vercel Services builds the Vite frontend and Python API independently and ships them together. Services is a [Vercel beta feature](https://vercel.com/docs/services). The root `vercel.json` routes `/api/*` to the Python service and all other requests to the frontend. The backend entrypoint is `app:app`; the regular authenticated entrypoint remains `sentinelforge.main:app`.

Create a new Vercel project for this repository at the repository root. Do not set `SF_LOCAL_MODE`, database credentials or application tokens. Keep preview deployment protection enabled; the production demo is intentionally public. Deploy reviewed commits only. `.vercelignore` excludes local environment files, databases, dependencies and scratch outputs from CLI uploads. Git deployments contain only tracked files.

## Reproduce and verify

```sh
. .venv/bin/activate
python scripts/build_public_demo.py --check
pytest tests/test_public_demo.py
pnpm --dir frontend run build
python -m uvicorn app:app --host 127.0.0.1 --port 8002
```

In another terminal:

```sh
SF_PUBLIC_DEMO=1 SF_BASE_URL=http://127.0.0.1:8002 pnpm --dir frontend exec playwright test public-demo.spec.ts
```

To refresh the demo after changing fixtures or rules, run `python scripts/build_public_demo.py`, review its diff, then commit the new snapshot. A stale source digest fails closed at startup. Never generate this file from a real operator database.
