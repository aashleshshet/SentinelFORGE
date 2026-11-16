# Cyberpunk UI and product guide deployment

The user explicitly requested deployment after the UI review. The existing Vercel project was rebuilt for production from the exact tested Git preview, without merging the draft PR or changing authentication, deployment protection, environment credentials or CI target thresholds.

- Project: `sentinelforge` (`prj_odyoVI5sZitJkIXGRWuNFgc6J57H`), team `aashlesh-ramadas-shet`.
- Source: `1195a46594131c3648fcf6a521a009fe1ae770e4`, branch `feature/evidence-led-detection`.
- Production deployment: `dpl_9iVvPv3GjP2zudLE8pp85rPcuoed`, **READY**, approximately 40.2 seconds from build start to ready.
- Public URL: https://sentinelforge-theta.vercel.app
- Product overview: https://sentinelforge-theta.vercel.app/what-it-is
- Previous production deployment retained as a rollback candidate: `dpl_EtCxKpGMp4XfcEneFyLEwZCpKoT2`.

## Hosted verification

All **10 public browser tests passed against the production domain in 53.8 seconds**. Four authenticated-only tests were intentionally skipped because this is the read-only public deployment; their local verification is recorded in UI_REFINEMENT.md.

The production tests cover direct document routes, mode comparison, source disclosures, real evidence download, alert/source filtering, all nine rule definitions, refused demo mutation (HTTP 403), mobile menu and keyboard navigation, no horizontal overflow at 320/390/768/1440px, axe checks, reduced motion, opaque fallback, forced colors, lazy loading, delayed requests and route-asset error recovery. The expected synthetic read-only identity returned HTTP 200 with `demo: true`, `local: false`, role `viewer`. CSP, nosniff, frame denial and referrer policy were present.

The deployment-scoped production runtime scan for error/fatal logs returned no matching records in the post-release check window (2026-11-16 13:23–13:38 UTC). This is a point-in-time observation, not continuous monitoring.

## Browser lab observations

Two unthrottled Chromium samples, not field percentiles, INP measurements or Lighthouse scores:

| Route | LCP | CLS |
|---|---:|---:|
| `/` | 624 ms | 0.056306 |
| `/how-it-works` | 496 ms | 0.000087 |

Raw measurements are in `docs/design/cyberpunk-production-lab-metrics.json`. Both samples satisfy the existing CLS <0.1 regression check.

## Scope

The public site remains a fixed synthetic, read-only portfolio demo. Local operator data and credentials are not deployed. The requested UI and explanatory page are live, but the underlying platform remains experimental and the frozen detection acceptance targets remain unmet. The GitHub PR is still a draft and unmerged; deployment was a separate explicit user request. This record and related README corrections change documentation only after the verified release.
