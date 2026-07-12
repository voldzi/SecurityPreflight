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
paths, and release boundaries. SecurityPreflight consumes the published package
from the public npm registry.

## Decision

SecurityPreflight consumes `@voldzi/stratos-ui` as a direct Web UI dependency
from npm. The Web application imports the shared STRATOS stylesheet once from
the Next.js root layout and composes the dashboard from stable shared
primitives.

Current implementation uses STRATOS components and layout patterns:

- global application shell with a shared STRATOS topbar, left navigation, and a
  compact work surface;
- `AppShell`, `AppRail`, `WorkspaceSidebar`, `WorkspaceNav`, `GlobalTopbar`,
  `CommandCenter`, `ViewTabs`, `ViewToolbar`, `DataGridShell`, `DataTable`,
  `StructuredList`, `MetricCard`, `Badge`, `RagBadge`, `SelectField`, and
  `Button`;
- shared `@voldzi/stratos-ui/styles.css` tokens and component classes;
- hover/focus-only row actions through `StructuredList.actions`;
- actionable primary controls only when they are wired to API behavior.

The package integration must:

- consume `@voldzi/stratos-ui` from the public npm registry, not from a local
  `file:` path;
- keep repository, CI, and Docker builds free of `@voldzi` GitHub Packages
  registry overrides;
- keep peer dependencies compatible, especially React and `lucide-react`;
- import the shared package styles once from the Web application root;
- wrap STRATOS primitives with thin SecurityPreflight domain components rather
  than forking the shared library.

## Consequences

SecurityPreflight gets a STRATOS-aligned interface without path-based coupling
to the STRATOS monorepo. Local, CI, and Docker builds resolve the shared UI
package from npm without package credentials. UI changes should prefer shared
STRATOS primitives before adding new local component classes.
