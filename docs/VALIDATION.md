# Validation record

Recorded 2026-11-15 (Asia/Kolkata). All input telemetry is synthetic.

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
| PostgreSQL integration | Passed in GitHub Actions run [43700040298](https://github.com/aashleshshet/SentinelFORGE/actions/runs/43700040298), along with the backend and browser jobs |
| Complete Docker Compose deployment | CI caught a malformed temporary-filesystem mount and host access blocked by an internal-only API network. A quoted mount and separate loopback gateway address these issues; deployment revalidation is pending. Docker is not available on the development host |

## Actual fixes from validation

- The initial browser test searched for a rule title instead of the correlated case's first-signal title; the fixture locator now follows the actual case contract.
- Switching authenticated users retained the previous view; sign-in now returns to Overview.
- Controlled checklist state waited for the server; it now updates immediately and rolls back on failure.
- The mobile “Detection rules” navigation label touched the screen edge; the mobile label is now “Rules” with the full accessible name retained.
- The initial overview sorted solely by time and could hide older critical signals; it now shows highest-severity signals first, then most recent within severity.
- Adapter parsing failures are handled before persistence; internal detection/database exceptions propagate and roll back the transaction.
- Docker rejected a temporary-filesystem option parsed as a second mount because a comma-separated YAML scalar was unquoted. The mount is now one quoted string.
- The API was healthy inside its container but inaccessible from the host while attached only to an internal network. A separate loopback-bound gateway now forwards to one fixed API upstream. The API and PostgreSQL remain exclusively on the internal network. Automatic approval review rejected attaching the API itself to an external-capable bridge; that change was removed.

One dependency emits a Starlette warning that its httpx-based TestClient path is deprecated. It does not fail the suite; migration to the upstream replacement is planned after compatibility review. The repository does not suppress the warning.

The Impeccable helper could not run in this environment, and the independent review agent failed due to an account usage limit. A [screenshot review](design/finish-review.md) was performed in the main session; independent design review is therefore not claimed. The first TasteSkill browser inspection identified the mobile label and compact type. After corrections, its follow-up inspection timed out during browser navigation; a clean inspector pass is not claimed. The completed Playwright run and final rendered captures provide the responsive evidence. Dense metadata uses 11–12px type; task text is 13px, with no text below 11px.

## Reproducibility and limits

`requirements.lock`, `requirements-runtime.lock` and `frontend/pnpm-lock.yaml` pin the measured installations. CI has separate backend/PostgreSQL, browser, and Compose jobs. CI results are linked from the repository Actions page; a workflow file alone is not evidence that it passed. Screenshots under `docs/screenshots` were captured from the compiled React application using only demo telemetry.

No live Windows/Linux/Wazuh/Zeek deployment, enterprise throughput test, independent detection corpus, penetration test or production security review has been performed. See README's implemented/planned table and the threat model.
