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
- Confirm the PostgreSQL service is running.
- Check `DATABASE_URL` against `docs/operations.md` and `.env.example`.
- Restart only the database service when possible, then recheck `/ready`.

## External Service Is Unavailable

- For MVP, required external services are local Compose services and scanner
  containers.
- If a vulnerability database update fails, rerun the profile with network
  access disabled or retry when network access is available.
- If a DAST target is unavailable, verify it is a permitted localhost or
  allowlisted staging host before retrying.

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
