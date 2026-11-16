# SentinelForge

**Evidence before action.** A working defensive engineering lab that turns attributed telemetry into explainable detections, incident cases, and preserved evidence.

Built for SOC and detection-engineering portfolios: Python 3.12 / FastAPI / SQLAlchemy / PostgreSQL, with a React / TypeScript / Tailwind dashboard. MIT licensed. This is an experimental single-tenant platform, not an enterprise SIEM or a substitute for a reviewed incident-response process.

**[Open the public demo](https://sentinelforge-theta.vercel.app)** — no sign-in; read-only synthetic telemetry. **[How It Works](https://sentinelforge-theta.vercel.app/how-it-works)** walks through the real workflow. Use the local setup below for the full investigation workspace.

See the [modernization and validation report](docs/MODERNIZATION.md) for the midnight glass interface, accessible guide and release evidence.

![SentinelForge dashboard showing synthetic lab telemetry](docs/screenshots/desktop.png)

The public demo includes a detailed **[What It Is](https://sentinelforge-theta.vercel.app/what-it-is)** tab, a cyberpunk palette and interaction recovery improvements. See [UI refinement and validation](docs/UI_REFINEMENT.md). Commit `1195a46` was deployed directly at the user’s request; the source PR remains a draft and is unmerged.

## What you can do

1. Ingest Linux authentication, assembled auditd, Sysmon JSON, Wazuh alert JSON, Zeek conn.log JSON, and synthetic events.
2. Normalize timestamps and attribution, reject invalid records, and deduplicate exact content replays.
3. Run nine experimental rules using a documented Sigma subset; attach official MITRE ATT&CK metadata and exact event evidence.
4. Correlate alerts by host or non-generic user in a 15-minute activity window; inspect the grouping reason and risk calculation.
5. Assign/escalate/close cases, add notes and checklists, preserve a SHA-256-verified snapshot, and export a JSON incident report.
6. Request simulated isolation with a separate administrator's approval. No endpoint commands are ever executed.

## Run locally — no token or sign-in

The local launcher opens the dashboard directly as a shared local analyst. It binds only to `127.0.0.1` and rejects non-loopback and cross-origin access. SQLite stores the local workspace.

```sh
git clone https://github.com/aashleshshet/SentinelFORGE.git
cd SentinelFORGE
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
npm install --global pnpm@11.25.0
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend run build
python scripts/run_local.py
```

Open **http://127.0.0.1:8000** and select **Replay demo**. No access token is required. A clean workspace yields **18 events, 7 alerts, and 2 investigations**. Stop with Ctrl+C; restart with `python scripts/run_local.py`. Do not proxy this mode onto another network. Any program on your computer that can access loopback shares the local analyst's privileges.

For a two-person approval/RBAC demonstration or PostgreSQL deployment, use authenticated mode below.

## Authenticated Docker Compose deployment

For the hosted read-only portfolio version, see [Vercel deployment](docs/VERCEL.md). It uses bundled synthetic telemetry and requires no sign-in. Local mode above supports the full editing workflow.

Requirements: Docker Engine with Compose v2, Git, and Python 3.12+. A small Nginx gateway publishes the dashboard on loopback only. The API and PostgreSQL stay on an internal Compose network.

```sh
git clone https://github.com/aashleshshet/SentinelFORGE.git
cd SentinelFORGE
python3 scripts/setup.py
docker compose up --build --detach --wait
```

Open **http://127.0.0.1:8000**. Open your generated `.env` locally and copy the token for `lead` into the access-token form. Select **Replay demo**. A clean database produces **18 normalized events, 7 alerts, and 2 cases**. The demo is entirely synthetic; command strings are stored as data and are never executed.

`setup.py` creates unique secrets with owner-only file permissions. It never overwrites an existing `.env`. The four identities are `lead` (admin), `analyst`, `reviewer` (viewer), and `collector` (ingest only). In authenticated mode, the browser keeps the token in memory; a page reload requires sign-in again. Never commit `.env` or paste a token into an issue.

```sh
docker compose logs --tail=100 api
docker compose down                 # preserves the named database volume
```

All three CI jobs passed: SQLite and PostgreSQL contracts, the real browser/API workflow, and a complete Compose build/replay. See the [recorded run and validation limits](docs/VALIDATION.md).

## Authenticated development mode (optional)

Requires Python 3.12+, Node 24, and pnpm 11.25.0. SQLite is the default local database.

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
python -m pip install --no-deps -e .
python scripts/setup.py
npm install --global pnpm@11.25.0
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend run build
python -m uvicorn sentinelforge.main:app --host 127.0.0.1 --port 8000 --no-access-log --no-proxy-headers
```

For UI development, run `pnpm --dir frontend dev` in a second terminal. Vite forwards `/api` to port 8000. To use PostgreSQL locally, set `SF_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE`. Schema v1 is created at startup; upgrades currently require an explicit migration plan and database backup.

## Validate it

```sh
pytest --cov=sentinelforge --cov-report=term-missing
ruff check backend tests scripts
python scripts/evaluate.py
python scripts/benchmark.py --events 1000 --runs 3
pnpm --dir frontend run build
pnpm --dir frontend exec playwright install chromium
# Start the API first, with generated .env credentials and a clean demo database:
pnpm --dir frontend exec playwright test
pip-audit -r requirements.lock
pnpm --dir frontend audit --audit-level high
```

The preserved legacy toy corpus deliberately includes failures: **7 TP, 2 FP, 7 TN, 2 FN**; precision **77.8%**, recall **77.8%**, false-positive rate **22.2%**. These are scenario-level synthetic results, not real-world efficacy estimates. See [evaluation methodology and measured latency/throughput](docs/EVALUATION.md), [raw evaluation results](docs/evaluation-results.json), and [benchmark results](docs/benchmark-results.json).

The [evidence-led improvement report](docs/DETECTION_IMPROVEMENT.md) records separately frozen synthetic datasets, scoped administrative approvals and two context-supported rules. On its 16-case holdout the candidate measures 83.33% precision, 62.50% recall, 75.00% accuracy and 12.50% FPR: **the requested targets remain unmet**. These co-designed synthetic cases are not independent deployment validation. The strict CI target gate remains failing.

The subsequent [command accuracy upgrade](docs/ACCURACY_UPGRADE.md) fixes option/value confusion in PowerShell, scheduled tasks, UID-zero and sudo evidence. On a new 40-case synthetic challenge holdout, accuracy rises **70% → 87.5%**, precision **64.29% → 85.71%**, and false alerts fall **10 → 3**, with recall unchanged at 90%. All 120 new rule contracts and 260 Python tests pass. This is narrow synthetic evidence, not operational accuracy; the original metrics and failing acceptance gate remain unchanged. The upgrade is live in the [public synthetic demo](https://sentinelforge-theta.vercel.app) at source `0aa1103`; all 10 hosted public browser tests pass. The source PR remains draft and unmerged; see the [verified release record](docs/ACCURACY_UPGRADE.md#public-production-release).

## Replay your own telemetry

Create a JSON array of envelopes or an object with an `events` array. In the token-free local dashboard, open **Telemetry → Import JSON** to upload it directly. For the authenticated command-line replay tool, set `SF_TOKEN` to the collector token without placing it in shell history (for example, use your shell's hidden-input prompt), then run:

```sh
python scripts/replay.py data/demo.json
```

```json
{
  "source": "linux_auth",
  "sensor": "edge-auth-01",
  "payload": "2026-11-15T09:00:01Z edge-01 sshd[1001]: Failed password for analyst from 192.0.2.45 port 51000 ssh2"
}
```

An ingestion call returns per-event `accepted`, `duplicate`, or `rejected` outcomes. A batch accepts up to 200 envelopes and 1 MiB; each raw payload is capped at 64 KiB. See [API contracts](docs/API.md) and [adapter formats](docs/TELEMETRY.md).

## Example investigation

After replay, open **Investigations → SSH password guessing · edge-01**. The case combines SSH failures, a shell TCP redirection, UID-zero account creation, and a root shell through sudo. The timeline keeps their original timestamps. The account event arrives late in the demo on purpose; the correlator accepts out-of-order evidence.

Assign the case, mark it Investigating, record a note, and preserve evidence. Export the snapshot and verify it with:

```sh
python scripts/verify_evidence.py path/to/sentinelforge-case-ID.json
```

For the approval flow, sign in as `analyst`, request a simulation, then sign in as `lead` to approve it. Self-approval is rejected server-side. See [incident response](docs/INCIDENT_RESPONSE.md).

## Implemented versus planned

| Capability | Status |
|---|---|
| Six ingestion formats, normalization, UTC validation, deduplication | Implemented; adapter fixtures and API tests |
| Nine detections with exact evidence and ATT&CK mapping | Implemented; experimental, synthetic validation only |
| Sigma workflow | Bounded dictionary/boolean subset; custom SSH aggregation extension |
| Explainable correlation, risk, notes, assignment, escalation, checklist | Implemented |
| Responsive dashboard, search, source/severity/technique filters | Implemented; real API data, 10-second polling |
| Immutable-by-API evidence snapshots and JSON report export | Implemented; SHA-256 integrity, not WORM or signed custody |
| Local IP IOC lookup | Implemented; no third-party egress |
| MITRE STIX data | Bundled eight-technique subset; explicit operator refresh script |
| Auth, RBAC, request limits, structured logs, hardened API container | Implemented for a local single-tenant lab |
| Wazuh server/agents, live log tailers, auditd assembly, XML/EVTX parsing | Planned; only import formats are implemented |
| Full Sigma/pySigma compiler and Sigma correlation specification | Planned |
| VirusTotal / AbuseIPDB | Planned; intentionally no client or automatic disclosure |
| OpenSearch, streaming queue, distributed workers, retention automation | Planned; PostgreSQL suffices for this MVP |
| OIDC/MFA, per-host collector authorization, tenant isolation, signed evidence | Planned |
| Real containment, antivirus, remediation, endpoint control | Not implemented |

## Documentation

- [Architecture](ARCHITECTURE.md) and [API/OpenAPI contracts](docs/API.md)
- [Detection rules](docs/DETECTION_RULES.md) and [ATT&CK coverage](docs/ATTACK_COVERAGE.md)
- [Incident response](docs/INCIDENT_RESPONSE.md) and [threat model](docs/THREAT_MODEL.md)
- [Evaluation](docs/EVALUATION.md), [security policy](SECURITY.md), [contributing](CONTRIBUTING.md)

MITRE ATT&CK content is attributed separately in [NOTICE](NOTICE). Screenshots contain only the bundled synthetic lab data. No third-party telemetry or credentials are shipped.
