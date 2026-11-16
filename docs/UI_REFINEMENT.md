# Product overview and cyberpunk UI refinement

The 2026-11-16 review-branch update adds a detailed **What It Is** tab and improves the existing analyst interface. This is a UI quality pass for an experimental defensive lab, not a claim that the detection engine or deployment is production-ready. The frozen detection targets remain unmet. No rules, evaluation inputs, authentication policy or public-demo mutation boundary changed in this update.

## Experience

- `/what-it-is` explains purpose, intended users, event → alert → case → evidence concepts, six source formats, nine experimental rules, context provenance, three workspace modes and evidence/response limits. An interactive mode comparison is explanatory and never changes access permissions.
- The new tab appears alongside How It Works in desktop, mobile and signed-out navigation. Both pages have direct HTML entries, metadata, no-JavaScript descriptions and exact FastAPI/Vercel routes. In-app links retain memory-only credentials. A failed lazy page load offers reload or return to the existing workspace.
- Near-black surfaces, electric cyan actions and restrained magenta accents replace the navy palette. Opaque evidence panels, self-hosted fonts, labelled severity colors, selective glass, forced-color and reduced-motion behavior remain intact. A local SVG favicon avoids a missing browser asset.
- Filter/view-specific loading prevents old rows from appearing under new filters. Search inputs retain focus and Clear filters provides recovery. Pagination clamps when results shrink.
- Read failures and action errors have separate messages. Successful polling does not erase failed-import or save feedback. Mutations have scope guards, changed drafts survive delayed saves, and old case responses cannot replace a newly opened case. Failed actions during initial loading recover the view. Repeated active-view navigation does not strand Refresh.
- Opening a case moves focus to its investigation. Returning restores the triggering row and previous list scroll. Authenticated token input is disabled during sign-in; sign-out clears retained state.

## Verification

- TypeScript and Vite production build pass; no dependency added. Initial JS is 83.60 kB gzip and initial CSS 10.90 kB gzip. What It Is is lazy: 5.79 kB JS and 1.93 kB CSS gzip. The added page does not ship in the workspace's initial JS.
- **160 Python tests pass, 95.57% coverage** (85% gate); Ruff lint/format and affected frontend Prettier checks pass. Exact document routes and API authorization boundaries are exercised.
- **19 browser tests pass:** nine authenticated tests against an isolated SQLite workspace and ten against the immutable synthetic public demo. These include real replay, notes, checklist, evidence export, simulation request, viewer restrictions, session retention, delayed filters, failed imports, stale mutation responses, missing document assets and repeated navigation. Opposite-mode tests are intentionally skipped in each run and executed in the other.
- Axe checks all workspace views, case detail, How It Works, the mobile dialog and What It Is at 1440, 768, 390 and 320px. Responsive screenshots, keyboard navigation, focus restoration, forced colors, reduced motion, opaque fallback and existing 200% zoom checks pass. Native browser inspection confirms the new page and mode comparison.
- Current screenshots are in `docs/screenshots/`. The two unthrottled Chromium route samples in `docs/design/cyberpunk-lab-metrics.json` retain the CLS <0.1 check. They are local lab samples, not field percentiles, INP, Lighthouse scores or performance guarantees.

Commands: `pnpm --dir frontend run build`, `ruff check backend tests scripts`, `ruff format --check backend tests scripts`, `pytest --cov=sentinelforge --cov-fail-under=85`, and the existing Playwright configuration against the authenticated and public-demo servers. Public CI includes `ux-hardening.spec.ts` as well as the existing public and modernization suites.

## Review boundary

The update stays on draft PR #2. No automatic merge or production promotion is performed. Automated accessibility checks do not replace manual screen-reader, Safari/Firefox or physical-device testing. The broader detection, retention, identity and deployment limitations remain documented in SECURITY.md and DETECTION_IMPROVEMENT.md.
