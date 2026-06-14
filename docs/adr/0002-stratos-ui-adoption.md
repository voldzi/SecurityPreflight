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

SecurityPreflight consumes `@voldzi/stratos-ui` as a direct Web UI dependency
through GitHub Packages. The Web application imports the shared STRATOS
stylesheet once from the Next.js root layout and composes the dashboard from
stable shared primitives.

Current implementation uses STRATOS components and layout patterns:

- global application shell with left navigation and a compact work surface;
- `AppShell`, `AppRail`, `WorkspaceSidebar`, `WorkspaceNav`, `Topbar`,
  `ViewTabs`, `ViewToolbar`, `DataGridShell`, `DataTable`, `StructuredList`,
  `MetricCard`, `Badge`, `RagBadge`, `SelectField`, and `Button`;
- shared `@voldzi/stratos-ui/styles.css` tokens and component classes;
- actionable primary controls only when they are wired to API behavior.

The package integration must:

- consume `@voldzi/stratos-ui` from GitHub Packages or another approved
  registry, not from a local `file:` path;
- keep package credentials out of Git, shell history, Dockerfiles, and reports;
- pass package credentials to Docker builds through build secrets such as a
  user-local `.npmrc`;
- keep peer dependencies compatible, especially React and `lucide-react`;
- import the shared package styles once from the Web application root;
- wrap STRATOS primitives with thin SecurityPreflight domain components rather
  than forking the shared library.

## Consequences

SecurityPreflight gets a STRATOS-aligned interface without path-based coupling
to the STRATOS monorepo. Local and CI environments must provide read-only
GitHub Packages access for `@voldzi/stratos-ui` during Web dependency
installation. UI changes should prefer shared STRATOS primitives before adding
new local component classes.
