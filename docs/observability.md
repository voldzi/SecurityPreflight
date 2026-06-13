# Observability

## Logging

Logs are structured JSON with the required fields:

```text
timestamp, level, service, message, requestId, environment, version
```

and when relevant: `userId`, `tenantId`, `operation`, `durationMs`,
`errorCode`, `traceId`, `spanId`.

The API and worker will use structured JSON logging. Scanner output is treated
as untrusted and potentially sensitive: logs must not contain bearer tokens,
passwords, cookies, private keys, production `.env` values, or full sensitive
payloads.

## Metrics

MVP metrics should cover scan duration, queue wait time, scanner duration,
scanner exit status, timeout count, finding counts by severity, gate results,
report generation duration, and API request latency.

## Tracing

OpenTelemetry is the preferred tracing standard. MVP can start with request IDs
and structured logs, then add OpenTelemetry spans for API requests, queue jobs,
scanner execution, parsing, normalization, gate evaluation, and report
generation.

## Observability Stack

OpenTelemetry is the preferred standard. If this project uses something else,
state here: why OpenTelemetry is not used, what is used instead, how logs,
metrics, and traces are collected, and how the data reaches monitoring.

## Correlation / Request ID

Every request gets a `requestId`; it is propagated to logs and error responses.

The API generates a request ID for each incoming request unless a trusted local
client provides one. Scan jobs carry the originating request ID and scan ID into
worker logs and audit events.

## Health and Readiness Rules

- `/health` reports process liveness only.
- `/ready` returns 200 only when required dependencies are usable, 503 otherwise.

## Alerts

MVP has no external alerting. The UI and CLI surface failed scans, scanner
timeouts, tool unavailability, invalid OpenAPI files, and failed readiness
checks.

## Dashboards

The Web UI dashboard shows local scan health: recent scans, gate results,
critical/high finding counts, scanner availability, and failed jobs.
