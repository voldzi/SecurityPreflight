# ADR 0002: STRATOS UI Adoption Path

## Status

Accepted

## Context

SecurityPreflight is part of the STRATOS application group and should follow
the same interface principles as the existing STRATOS applications. The
canonical shared component library is `@voldzi/stratos-ui`, maintained in the
STRATOS workspace under `packages/stratos-ui`.

STRATOS documentation defines external consumption through the package
registry. External applications must not depend on the STRATOS workspace with a
local `file:` dependency because that couples Docker build contexts, developer
paths, and release boundaries. Registry access requires a read-only package
token supplied outside Git and outside committed Docker or environment files.

## Decision

SecurityPreflight will align its Web UI with STRATOS shell principles now and
adopt `@voldzi/stratos-ui` as a package dependency after package registry
access is configured for local and CI builds.

Current implementation uses STRATOS-compatible design tokens and layout
patterns:

- global application shell with left navigation and a compact work surface;
- restrained status chips, panels, tables, and operational controls;
- `--stratos-*` token names for color, radius, and shadow primitives;
- actionable primary controls only when they are wired to API behavior.

The future direct package integration must:

- consume `@voldzi/stratos-ui` from GitHub Packages or another approved
  registry, not from a local `file:` path;
- keep package credentials out of Git, shell history, Dockerfiles, and reports;
- verify peer dependency compatibility before merging, especially React and
  `lucide-react`;
- import the shared package styles once from the Web application root;
- wrap STRATOS primitives with thin SecurityPreflight domain components rather
  than forking the shared library.

## Consequences

SecurityPreflight gets a STRATOS-aligned interface immediately without adding
fragile path-based coupling to the STRATOS monorepo. The remaining work is
configuration, not product design: package registry access must be added to the
developer and CI environments before the shared package can become a direct
runtime dependency.

Until that registry access exists, UI changes should continue using the local
STRATOS-compatible tokens and should avoid introducing alternate design systems
or one-off component libraries.
