# Validation record

Recorded 2026-11-15 (Asia/Kolkata). All input telemetry is synthetic.

## Detection-improvement candidate

The unmerged evidence-led candidate passes 159 local Python tests with 95.32% coverage, all 11 browser tests, TypeScript/Vite, Ruff/Prettier, deterministic generation and dependency audits. The separate detection target gate fails honestly on the designated synthetic holdout: precision 83.33%, recall 62.50%, accuracy 75.00%, FPR 12.50%. See [full before/after evidence and limitations](DETECTION_IMPROVEMENT.md) and [validation logs](evidence/detection-improvement/validation/). Earlier release records below are historical.

## Modernization release

Commit [`5d1fed0`](https://github.com/aashleshshet/SentinelFORGE/commit/5d1fed097244fd5b32572e4f7e9d2cd983474716) passed all three jobs in [CI run 43728447649](https://github.com/aashleshshet/SentinelFORGE/actions/runs/43728447649), including PostgreSQL contracts and the full Docker Compose deployment. Local validation recorded 61 Python tests with 94.92% statement coverage. All 11 browser tests pass in CI: five authenticated and six public-demo/guide tests. The six public tests also pass on the deployed application code.

The production TypeScript/Vite build, Ruff, Prettier, snapshot reproducibility and dependency audits pass. Automated accessibility checks cover all five views, case detail, the guide and mobile dialog; responsive checks include 320px, keyboard navigation, focus restoration, reduced motion and forced colors. Two real defects found during validation were corrected: delayed guide styles shifted the page, and the contrast test sampled an animating dialog. See the [modernization report](MODERNIZATION.md) for exact asset sizes, production-domain lab measurements, screenshots, security findings, deployment evidence and remaining limitations.

## Historical public-demo and local-workspace validation

Public Vercel demo addition: **60 backend tests passed, 95% statement coverage**, including cross-instance stable IDs, credential/environment isolation, immutable SQLite enforcement, evidence integrity and rejection of all nine mutation routes. The dedicated public browser test passed locally and on the production Vercel domain with no sign-in, filters, evidence download and a 390px overflow assertion. All three CI jobs passed for the demo code. See [hosted verification](VERCEL.md#recorded-verification). The historical full local-workspace validation below remains applicable to its original commit.

| Check | Observed result |
|---|---|
| Python API/adapter/rule/correlation/security suite | 47 passed; 94% statement coverage |
| Ruff lint and formatting | Passed |
| React TypeScript check and Vite production build | Passed |
| Browser workflow on real API | 3 passed: replay, case assignment/status, notes, checklist, evidence download, simulation request, filters, raw normalized-event display, rule expansion and viewer UI restrictions |
| Responsive pages | 1440px, 768px, 390px; no horizontal page overflow in automated assertions |
| Token-free local mode | Direct browser observation and API tests; loopback host/peer restriction, cross-origin/fetch rejection, and no fallback on invalid bearer token |
| Python dependency audit | No known vulnerabilities in the locked dependency set |
| Frontend dependency audit | No known vulnerabilities in the scanned dependency set; re-run after dependency updates |
| Scenario evaluation | 7 TP, 2 FP, 7 TN, 2 FN; failures retained in the dataset |
| Throughput benchmark | Three SQLite/WAL runs; median 6,072.36 events/s for the stated benign batch workload |
| PostgreSQL integration | Passed in GitHub Actions run [43701088632](https://github.com/aashleshshet/SentinelFORGE/actions/runs/43701088632), along with the backend and browser jobs |
| Complete Docker Compose deployment | Passed in the same run: image build, three healthy services, host HTTP health check, authenticated ingestion, seven alerts and persisted cases. Earlier failures and fixes are recorded below. Docker is not available on the development host; this evidence is from the Linux CI runner |

## Actual fixes from validation

- The initial browser test searched for a rule title instead of the correlated case's first-signal title; the fixture locator now follows the actual case contract.
- Switching authenticated users retained the previous view; sign-in now returns to Overview.
- Controlled checklist state waited for the server; it now updates immediately and rolls back on failure.
- The mobile “Detection rules” navigation label touched the screen edge; the mobile label is now “Rules” with the full accessible name retained.
- The initial overview sorted solely by time and could hide older critical signals; it now shows highest-severity signals first, then most recent within severity.
- Adapter parsing failures are handled before persistence; internal detection/database exceptions propagate and roll back the transaction.
- Docker rejected a temporary-filesystem option parsed as a second mount because a comma-separated YAML scalar was unquoted. The mount is now one quoted string.
- The API was healthy inside its container but inaccessible from the host while attached only to an internal network. A separate loopback-bound gateway now forwards to one fixed API upstream. The API and PostgreSQL remain exclusively on the internal network. Automatic approval review rejected attaching the API itself to an external-capable bridge; that change was removed.
- The unprivileged gateway requires every module's temporary directory under writable `/tmp`, following [Nginx's unprivileged configuration guidance](https://github.com/nginx/docker-nginx-unprivileged#troubleshooting-tips). Its readiness probe explicitly performs a GET through the gateway to the API.

One dependency emits a Starlette warning that its httpx-based TestClient path is deprecated. It does not fail the suite; migration to the upstream replacement is planned after compatibility review. The repository does not suppress the warning.

The Impeccable helper could not run in this environment, and the independent review agent failed due to an account usage limit. A [screenshot review](design/finish-review.md) was performed in the main session; independent design review is therefore not claimed. The first TasteSkill browser inspection identified the mobile label and compact type. After corrections, its follow-up inspection timed out during browser navigation; a clean inspector pass is not claimed. The completed Playwright run and final rendered captures provide the responsive evidence. Dense metadata uses 11–12px type; task text is 13px, with no text below 11px.

## Reproducibility and limits

`requirements.lock`, `requirements-runtime.lock` and `frontend/pnpm-lock.yaml` pin the measured installations. CI has separate backend/PostgreSQL, browser, and Compose jobs. All three passed for code commit `03b5b3b7d3b39b5a06be2902b38a574491b55eab` in [run 43701088632](https://github.com/aashleshshet/SentinelFORGE/actions/runs/43701088632). This validation-record update changes documentation only. Screenshots under `docs/screenshots` were captured from the compiled React application using only demo telemetry.

No live Windows/Linux/Wazuh/Zeek deployment, enterprise throughput test, independent detection corpus, penetration test or production security review has been performed. See README's implemented/planned table and the threat model.
