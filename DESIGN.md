# SentinelForge design system

A midnight work surface for evidence-led investigation. The November 2026 modernization replaces the original charcoal rail with layered navy materials, pill controls and a readable workspace sidebar. Preserve the real API, severity meanings and analyst workflows.

## Tokens and typography

`frontend/src/modern.css` owns shared material tokens; `style.css` retains established evidence/table layouts and `guide.css` owns the lazy-loaded guide layout.

| Token | Value |
|---|---|
| Canvas / surface / raised | `#080D19` / `#101A2C` / `#17243A` |
| Text / secondary / accent | `#F2F6FC` / `#B4C2D8` / `#8CCBFF` |
| Boundary / control boundary | `#2B3B53` / `#647995` |
| Glass | 88% navy, 16px blur, 135% saturation, 21% pale-blue edge |
| Control / panel radius | 999px / 16–20px |
| Motion | 120 / 180 / 240ms; cubic-bezier(.2,.8,.2,1) |

Self-hosted Public Sans provides interface text; IBM Plex Mono identifies timestamps, IDs and measured counts. Body text is 14px, guide prose 14–16px, metadata 11–12px. Large headings and counts establish hierarchy without changing the meaning of the underlying data. Color-coded severity always includes a text label.

## Material and components

Use glass for navigation and modal chrome. Use opaque panels and evidence surfaces for sustained reading; never add a backdrop filter per row or nested scrolling layer. Fine edges, inset highlights and restrained blue/violet reflections add depth. Opaque surfaces are the base fallback, with blur enabled only through `@supports`; reduced transparency and forced colors have explicit treatments.

`components/glass.tsx` centralizes native Button, Input, Panel, Navbar, Sidebar, Table and Modal primitives. Existing semantic selects and details provide dropdowns and accordions. No extra UI or motion library is required. Native dialog behavior supplies inert background/Escape/focus restoration, with explicit first/last keyboard wrapping for consistent platform behavior.

## Navigation and layout

Desktop uses a 224px labeled sidebar that collapses to 80px. Tablet uses the compact rail; mobile uses a named, keyboard-accessible modal menu. Controls generally target 44px; compact data links retain readable spacing. Tables scroll within their work panels, not across the page. Safe-area spacing protects mobile dialogs and footers.

Five workspace destinations use validated `?view=` URLs. `/how-it-works` is a lazy-loaded route with its own built HTML entry and metadata. Internal navigation preserves in-memory authentication. Back/forward clears stale filters and case selection. The public header shows guide navigation; real local or authenticated identity and sign-out controls remain mode-dependent. No fake user profile is shown.

## Motion and accessibility

Use short transform/opacity entrances, press feedback, chart entrances and progressive dialog transitions. Skeleton motion ends after three iterations. No perpetual ambient animation, parallax, animated blur or auto-moving evidence. Reduced motion removes nonessential transitions and animations.

Provide visible focus, semantic headings, labels, skip links, disclosure states, tab arrow/Home/End navigation and modal focus wrapping. Validate actual composited colors with axe and inspect rendered screenshots. Automated checks are not a WCAG certification or a replacement for manual assistive-technology testing.

## Product truth

All dashboard counts and timestamps come from the API. The guide diagram is explicitly an illustration. The public demo is a fixed synthetic snapshot, not a live feed. Local editing, API role checks, simulated responses and evidence integrity limits stay explicit. Do not invent AI, reputation services, native EVTX ingestion, real endpoint actions, signed custody or compliance claims.

The repository skill in `.agents/skills/sentinelforge-design-system` captures these conventions for future changes. See `docs/MODERNIZATION.md` for implementation and verification evidence.
