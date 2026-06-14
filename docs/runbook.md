# Runbook

Concrete steps for operational scenarios. Keep each scenario actionable:
symptoms, diagnosis, fix, verification.

## The Application Does Not Start

- Symptoms: Docker Compose service exits, Web UI is unavailable, API health
  check fails, or CLI `doctor` cannot reach the stack.
- Diagnosis: verify Docker Desktop is running, inspect Compose service status,
  and check API/worker logs for startup errors.
- Fix: correct invalid environment variables, free conflicting ports, restart
  Docker Desktop if needed, then restart the stack.

## API Returns 5xx

- Check logs filtered by `requestId` of a failing request.
- Verify PostgreSQL and Redis readiness.
- Check whether scanner output parsing failed for the relevant scan ID.
- Confirm errors returned to clients do not expose stack traces or secrets.

## Database Is Unavailable

- `/ready` should return 503.
- Confirm the PostgreSQL service is running or, in production on
  `docker.home.cz`, that `DATABASE_URL` points to the HAProxy endpoint
  `haproxy.home.cz:5000` with runtime-only credentials.
- Check `SECURITY_PREFLIGHT_DB_ENABLED` and `SECURITY_PREFLIGHT_DB_REQUIRED`.
  If DB is disabled, scan report evidence still works but finding triage and
  live progress persistence return a controlled API error.
- Check `DATABASE_URL` against `docs/operations.md` and `.env.example`.
- Restart only the database service when possible, then recheck `/ready`.

## External Service Is Unavailable

- For MVP, required external services are local Compose services and scanner
  containers.
- If a vulnerability database update fails, rerun the profile with network
  access disabled or retry when network access is available.
- If a DAST target is unavailable, verify it is a permitted localhost or
  allowlisted staging host before retrying.

## Docker Network Collides With LAN

- Symptoms: after starting SecurityPreflight, a real LAN host becomes
  unreachable from `docker.home.cz`; for example `nc -vz -w 5 192.168.200.2
  11434` returns `no route to host`.
- Diagnosis: inspect Docker IPAM and host routing:

```bash
docker network inspect $(docker network ls -q) \
  --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{end}}' \
  | grep '192.168.200' || echo OK

ip route get 192.168.200.2
```

- Fix: SecurityPreflight must use the explicit non-LAN Compose subnet
  `10.246.250.0/24`. Stop the stack, remove the previously created conflicting
  network, and restart:

```bash
docker compose --env-file .env -p securitypreflight \
  -f infra/docker-compose.yml \
  -f infra/docker-compose.production.yml \
  down
for network in security-preflight_default securitypreflight_default; do
  docker network inspect "$network" >/dev/null 2>&1 && docker network rm "$network"
done
docker compose --env-file .env -p securitypreflight \
  -f infra/docker-compose.yml \
  -f infra/docker-compose.production.yml \
  up -d --build
```

- Verification:

```bash
docker network inspect $(docker network ls -q) \
  --format '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{.Gateway}}{{end}}' \
  | grep '192.168.200' || echo OK
ip route get 192.168.200.2
nc -vz -w 5 192.168.200.2 11434
```

The route to `192.168.200.2` must not go through a Docker `br-*` interface.
Never configure SecurityPreflight Docker IPAM with `192.168.x.x` LAN ranges.

## Scan Evidence Is Missing or Skipped

- Check `REPORTS_PATH/<scanRunId>/execution-result.json`.
- Confirm the worker is running and consuming the `security-preflight-scans`
  queue.
- Internal check evidence should have one JSON file per step.
- External scanner steps write raw scanner evidence plus
  `<check>.command.json` and `<check>.execution.json` metadata.
- If an external scanner step is skipped, confirm `SCANNER_RUNNER_ENABLED` is
  not `false` and the scanner binary is present in the worker or selected
  scanner-toolbox image.
- For remote scanner runs, confirm `SCANNER_RUNNER_MODE=remote`,
  `SECURITY_PREFLIGHT_EXTERNAL_SCANNER_URL`, and
  `SECURITY_PREFLIGHT_EXTERNAL_SCANNER_PUBLIC_KEY`. If signatures are enforced,
  the remote response must include a detached signature over the payload.
- For Greenbone/OpenVAS, attach the approved XML or JSON report through
  `SECURITY_PREFLIGHT_GREENBONE_REPORT_PATH`; endpoint credentials alone are
  not enough to produce normalized vulnerability evidence.
- For OpenSCAP, attach `SECURITY_PREFLIGHT_OPENSCAP_RESULTS_PATH` or explicitly
  enable local evaluation with `SECURITY_PREFLIGHT_OPENSCAP_EVAL_ENABLED=true`,
  `SECURITY_PREFLIGHT_OPENSCAP_CONTENT_PATH`, and
  `SECURITY_PREFLIGHT_OPENSCAP_PROFILE`.
- For DefectDojo, inspect `defectdojo.sarif.json` and
  `defectdojo-delivery.json`. Upload requires
  `SECURITY_PREFLIGHT_DEFECTDOJO_EXPORT_ENABLED=true` and a resolvable token
  reference.
- For central telemetry, inspect `central-result-envelope.json` and
  `central-telemetry-delivery.json`.
- Do not treat a skipped external scanner step as a production pass.

## High Latency

- Identify whether latency is API request handling, queue wait time, scanner
  runtime, report generation, or database access.
- Check scanner timeouts and project size.
- Prefer `fast-local` for tight feedback loops.

## Memory or CPU Exhaustion

- Stop unnecessary scan runs.
- Use a lighter scan profile.
- Add scanner CPU/RAM limits in Docker Compose where practical.
- Avoid running multiple heavyweight scanners in parallel on small machines.

## Invalid Configuration

- Compare the environment against `docs/operations.md` configuration table
  and `.env.example`.
- Reject configurations that enable Docker socket access or active DAST unless
  the relevant explicit opt-in flags and allowlists are present.

## Rollback After a Failed Release

- MVP rollback is local: stop the stack, return to the previous git revision or
  previous images, and restart the stack.
- Do not delete report or database volumes unless intentionally discarding
  local scan history.

## Escalation

- Escalate to the project owner when scan evidence is missing, findings suggest
  exposed secrets, DAST touched an unintended target, or report redaction may
  have failed.
