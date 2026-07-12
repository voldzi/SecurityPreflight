# SecurityPreflight UX, Performance, AKB Audit

Date: 2026-06-30

## Implemented Now

- The new scan workflow keeps setup, live progress, evidence handoff, Codex
  export, and AKB AI summary in one place.
- The live scan panel was extracted into `ScanProgressPanel` so the main
  `page.tsx` can be split further without changing scan behavior.
- The latest scan card now offers direct AKB summarization through the existing
  server-side AKB bridge. Prompts, answers, chunks, and embeddings remain
  outside SecurityPreflight storage.
- The workflow uses shared STRATOS UI primitives for field help and select
  descriptions, including `HelpHint`, `FieldLabelWithHelp`, and `SelectField`
  accessory/description support.
- Safe minor or patch dependency updates were applied:
  - `bullmq` 5.79.x
  - `fastify` 5.9.x
  - `pg` 8.22.x
  - `autoprefixer` 10.5.x
  - `postcss` 8.5.x
  - `@types/node` 26.x

## Deliberately Deferred

These upgrades remain explicit migration work, not opportunistic updates:

- Next.js 16
- Tailwind CSS 4
- Zod 4
- Vitest 4
- Redocly CLI 2
- Commander 15
- `@fastify/cors` 11

Each deferred item can affect build output, validation semantics, middleware
behavior, or test execution and needs a dedicated regression pass.

## Next Refactoring Targets

- Split `apps/web/src/app/page.tsx` into feature components for scan setup,
  project registry, dashboard, execution detail, telemetry, and access-denied
  state.
- Move API fetching and derived scan state into hooks so UI components receive
  stable, narrow props.
- Add browser-level smoke tests for:
  - selecting a directory target,
  - selecting a Web/API target,
  - running dry-run and queued scan flows,
  - exporting Codex remediation,
  - asking AKB for a cited summary.
- Keep the primary user path simple: select target, select profile, run scan,
  review result, export handoff, ask AKB.
