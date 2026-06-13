# OpenAPI

This directory contains the machine-readable OpenAPI specification.

## Canonical Source

The primary and binding file is:

```text
openapi.json
```

## Optional Generated Files

`openapi.yaml`, if present, is only a generated export for tools or users who
prefer YAML. It must begin with:

```yaml
# This file is generated from openapi/openapi.json.
# Do not edit manually.
```

## Rule

Only `openapi.json` is edited by hand, or it is generated from code according
to the project standard. If the specification is generated from code, the
project documentation must describe where it is generated from, how it is
generated, how it is validated, and where it is published.

The human-readable API description lives in `docs/api.md`.
