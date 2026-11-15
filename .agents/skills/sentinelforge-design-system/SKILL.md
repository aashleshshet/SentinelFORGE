---
name: sentinelforge-design-system
description: Design, modernize, implement, or visually review SentinelForge frontend screens using its midnight liquid-glass design system while preserving security and API behavior. Use only for SentinelForge UI work, not unrelated apps or backend-only tasks.
metadata:
  version: "1.1.0"
---

# SentinelForge design system

Apply this direction to authorized UI work. Reusable native primitives live in `frontend/src/components/glass.tsx`; shared midnight tokens and material behavior live in `modern.css`, with guide-specific layout in `guide.css`. The guide is lazy-loaded, and Vite emits a separate HTML entry for `/how-it-works`. Read `PRODUCT.md`, `DESIGN.md`, `SECURITY.md`, `docs/THREAT_MODEL.md` and relevant source before editing. The frontend uses React 19, TypeScript, Vite 7, Tailwind 4, Public Sans, IBM Plex Mono and Lucide. Reuse the existing dependencies and build; do not migrate frameworks for a restyle.

The user requested midnight liquid-glass modernization. This intentionally supersedes the old `DESIGN.md` visual prohibitions on blur/gradients and its small control radii for that modernization. Retain its evidence-led workflows, truthful data, severity meanings and analyst readability. Update visual documentation only during authorized implementation. This skill does not itself authorize application edits or deployment.

## Security and behavior invariants

- Preserve API contracts, endpoint paths, types, filters, evidence exports, error handling, pending states and rollback on failed mutations. Counts and timestamps come from API data; never invent live telemetry or operational claims.
- Preserve memory-only bearer credentials, role checks, sign-in/sign-out and server authorization. Never persist tokens in localStorage, URLs, screenshots or logs; never substitute UI-only access checks.
- Keep authenticated operation, trusted loopback local mode and the public synthetic demo distinct. Public demo remains read-only with isolated synthetic data and rejected mutations. Never enable local mode or operator credentials on a public deployment.
- Retain two-person simulation approval, simulation-only semantics and restricted raw evidence access. Render telemetry/notes as untrusted text. Do not add unsafe HTML rendering, remote fonts, trackers or CSP relaxations for styling.
- Do not incidentally change auth, backend security, database or deployment boundaries. Identify and separately scope any interaction requiring a contract change.

## Visual direction and tokens

Create a premium cybersecurity work surface: midnight navy depth, restrained ice-blue highlights, precise hierarchy and calm data density. Avoid ornamental hacker imagery, neon everywhere, fictitious charts and glass on every record. Use glass chiefly for navigation, toolbars and overlays; use stable opaque surfaces for evidence and tables.

Centralize semantic CSS custom properties in the existing style system. These are starting targets, not prevalidated contrast pairs; test rendered combinations:

| Token family | Target |
|---|---|
| Canvas / opaque surface / raised | `#080D19` / `#101A2C` / `#17243A` |
| Text / secondary text / accent | `#F2F6FC` / `#B4C2D8` / `#8CCBFF` |
| Glass fill / edge | midnight navy at 80–90% opacity / pale blue at 16–24% opacity |
| Severity | preserve critical/high/medium/positive semantics, with labels and icons |
| Radius | controls/nav `999px`; panels `16–20px`; orderly compact data cells |
| Spacing | shared `4, 8, 12, 16, 24, 32, 48px` scale |
| Type | existing self-hosted Public Sans; IBM Plex Mono for IDs, timestamps and tabular values |
| Motion | `120ms`, `180ms`, `240ms`; shared `cubic-bezier(.2,.8,.2,1)` easing |

Use readable body sizing around 14–16px; reserve smaller metadata for secondary information and verify zoom. Extract reusable Button, IconButton, PillNav, GlassSurface, StatusBadge, Field and Dialog primitives when justified by repetition. Share hover, active, focus, disabled, loading and error states. Retain semantic links/buttons and accessible names.

## Authentic, accessible glass

- Combine translucent navy fill, backdrop blur around 12–20px, restrained saturation, a fine luminous edge, subtle inset highlight and soft directional shadow. Use a controlled tonal background so transmission is visible without reducing readability. Do not claim physical refraction for a CSS effect.
- Provide an opaque surface first; enhance with `@supports (backdrop-filter: blur(1px))` and supported prefixed equivalents. Keep text/icons fully opaque and preserve identical controls when filters are unsupported.
- Measure contrast on the composited result and worst expected background: at least 4.5:1 for normal text, 3:1 for large text and essential control/focus boundaries. Alpha borders alone are not reliable control boundaries.
- Provide solid treatments for forced-colors and supported reduced-transparency preferences. No moving distortion behind text or evidence.
- Make navigation and interactive controls pill-shaped with adequate padding; aim for 44px touch targets. Do not pill-shape dense tables. Indicate current navigation with shape/text as well as color.
- Preserve keyboard order, visible focus, dialog focus trapping/restoration, Escape behavior, screen-reader labels and non-color severity cues. Test 200% zoom and 320px reflow; tables may scroll within a labeled region rather than overflow the page.

## Motion and production performance

- Use shared duration/easing tokens for transitions; prefer opacity and small transforms. Avoid continuous pulse, parallax, tilt, bouncing panels and auto-moving decoration during investigation.
- Under `prefers-reduced-motion: reduce`, remove nonessential transforms, animated highlights/backgrounds, smooth scrolling and staged entrances. Essential state changes remain immediate and understandable.
- Never animate blur, shadows or layout dimensions on repeated lists. Avoid nested backdrop filters and full-screen repainting effects. Limit glass to a few visible layers; apply `will-change` temporarily only when profiling justifies it.
- Keep fonts self-hosted; do not add a motion/glass library where CSS suffices. Lazy-load noncritical imagery, declare dimensions, prefer optimized AVIF/WebP and keep decoration out of critical data paths.
- Compare production bundle and mobile rendering with the pre-change baseline. No unexplained dependency/bundle growth; investigate regressions before signoff. Target LCP <=2.5s, INP <=200ms and CLS <=0.1 at the 75th percentile where field data exists. Label lab measurements as lab evidence, never as field compliance.

## Verification and phase routing

Use this skill for visual decisions and installed Vercel `react-best-practices` for React review. Optional third-party Impeccable/Taste guidance must not override the requested glass/pill direction or security invariants. Do not invoke unrelated site-generation workflows for this existing repository.

Use native Codex browser control for interactive visual review and the repository's Playwright tests for repeatable regressions. Read current browser tool documentation; do not assume Playwright CLI or a separate REPL exists. Inspect screenshots at 390x844, 768x1024 and 1440x1000, plus 320px reflow, relevant breakpoints, keyboard focus, reduced motion, opaque fallback and loading/error/empty states. Check horizontal overflow and sticky controls covering content. Compare before/after screenshots using the same synthetic fixtures; inspect images rather than just checking files exist.

Use the installed `security-best-practices` skill for requested security reviews, with React and FastAPI reference guidance. Discover current tools before referring to Codex Security: that plugin was not available in the modernization session. Use repository tests, direct source review and dependency audits when it is unavailable; never claim an independent scan ran. Dependency audits do not replace security review.

For CI diagnosis, use the installed GitHub connector's workflow runs, steps/logs and artifacts; anchor results to the exact commit/attempt. Existing CI covers Python/Ruff/pytest/PostgreSQL, frontend build/audit/Playwright and Docker Compose. Preserve these checks and test affected behavior, including role denials and read-only demo behavior when touched.

For separately authorized releases, use Vercel `deployments-cicd`, `vercel-services`, `verification` and protected-deployment access guidance as needed. Read `docs/VERCEL.md`: this deploys a Vite frontend plus Python API, not Next.js. Verify deployment commit, health, demo identity, mutation rejection, assets, representative flows and runtime logs. READY alone is not end-to-end success.

Use built-in `imagegen` for requested documentation/visual assets. Distinguish illustrations from real application screenshots and security evidence. Do not send credentials or private telemetry in prompts.

Report changed components/tokens, preserved contracts, observed verification and checks that could not run. This skill provides instructions; it does not mechanically enforce CI gates.
