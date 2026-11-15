---
name: SentinelForge
description: Evidence-led security operations, designed for sustained investigation.
colors:
  ground: '#171719'
  surface: '#131217'
  raised: '#212023'
  border: '#2b2a2e'
  control: '#47464c'
  text: '#f2f2f3'
  muted: '#a3a3ac'
  accent: '#79a9df'
  critical: '#f48495'
  high: '#e9b17a'
  medium: '#d7c18b'
  positive: '#78c9a4'
typography:
  title:
    fontFamily: Public Sans, sans-serif
    fontSize: 26px
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: '-0.02em'
  body:
    fontFamily: Public Sans, sans-serif
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.65
  data:
    fontFamily: IBM Plex Mono, monospace
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: Public Sans, sans-serif
    fontSize: 11px
    fontWeight: 400
    lineHeight: 1.5
rounded:
  panel: 6px
  control: 5px
spacing:
  inline: 8px
  panel: 16px
  section: 24px
components:
  button-primary:
    backgroundColor: '{colors.text}'
    textColor: '{colors.ground}'
    rounded: '{rounded.control}'
    height: 35px
    padding: 0 14px
  panel:
    backgroundColor: '{colors.surface}'
    rounded: '{rounded.panel}'
    padding: 16px
---

## Overview

A quiet, dark operating surface. The analyst should recognize the queue, find exact evidence and record a decision without visual distraction. Product identity comes from the shield/stack mark, measured numeric typography and technique-count strips.

## Colors

Charcoal separates work areas by small tone changes. Blue identifies selections and ATT&CK count marks. Severity colors encode critical, high, medium and low signals with text labels; color is never the sole status cue. Body text and muted metadata remain readable against the surfaces.

## Typography

Public Sans carries interface language. IBM Plex Mono is reserved for identifiers, timestamps, commands and measurements. Large counts are regular weight; there is one page heading. Most metadata is compact at 11–12px, with task text at 13px. This density is deliberate for an analyst workstation; mobile content stacks instead of shrinking.

## Layout

A 62px desktop rail provides five destinations with accessible names. A compact bar names the product, local scope and active identity. Main gutters are 32px, with 24px gaps. At 1,100px the overview stacks. At 760px the rail becomes a labeled bottom navigation bar; case controls and timelines become a single column. Tables have contained horizontal overflow where needed, rather than widening the page.

## Elevation & Depth

Flat surfaces and quiet rules separate information. No glow, gradient, ornamental blur or floating decorative elements. No card shadows.

## Shapes

Small panel/control corners soften dense structures. The user identity alone is circular. Selection uses a narrow line. Technical records and timelines remain rectangular and orderly.

## Components

Primary actions use a pale fill; secondary controls use borders. Every icon-only control has an accessible label. Focus rings are visible; reduced-motion preferences disable transitions. Filter bars sit over their affected list. Empty, error, loading and disabled states retain clear wording. Errors preserve the last successful data with a stale-data notice.

The ATT&CK signal strip opens a technique-filtered alert list. Cases expose UTC chronology, exact evidence, authored rationale and separate simulated-response approval. Checkbox feedback updates immediately, then reconciles with the API or rolls back on failure.

## Do's and Don'ts

- Do derive counts and timestamps from the API.
- Do use semantic labels next to status colors.
- Do distinguish observed signals from compromise conclusions.
- Do keep data typography tabular and columns aligned.
- Don't invent live integrations, traffic histories or efficacy claims.
- Don't add decorative imagery, animations, gradients or neon glows.
- Don't put implementation details in the analyst's task flow unless they explain a decision or a genuine limit.
