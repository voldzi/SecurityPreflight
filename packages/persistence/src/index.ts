import path from "node:path";
import { Pool, type PoolClient } from "pg";
import type { Finding, FindingStatus, GateResult, ScanStatus, SeveritySummary } from "@security-preflight/core";

export type PersistenceStatus = "disabled" | "unavailable" | "ok";

export type PersistenceResult<T> =
  | {
      ok: true;
      status: "ok";
      data: T;
    }
  | {
      ok: false;
      status: Exclude<PersistenceStatus, "ok">;
      message: string;
    };

export interface PersistedScanRunSummary {
  id: string;
  status: ScanStatus | "unknown";
  gateResult: GateResult | "unknown";
  project: {
    id: string;
    name: string;
    dataClassification: string;
  };
  profile: {
    id: string;
    name: string;
  };
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  findingCount: number;
  severitySummary: SeveritySummary;
  evidence: {
    root: string;
    files: string[];
    hasExecutionResult: boolean;
    hasJsonReport: boolean;
    hasMarkdownReport: boolean;
    hasCentralEnvelope: boolean;
    hasSarifReport: boolean;
    hasCentralTelemetryDelivery: boolean;
    hasDefectDojoDelivery: boolean;
  };
}

export interface PersistedScanRunDetail extends PersistedScanRunSummary {
  gate: {
    result: GateResult | "unknown";
    blockingReasons: string[];
  };
  findings: PersistedFindingDto[];
  steps: PersistedScanStepDto[];
}

export interface PersistedFindingDto {
  id: string;
  tool: string;
  type: string;
  severity: string;
  title: string;
  filePath: string | null;
  line: number | null;
  endpoint: string | null;
  status: string;
  recommendation: string;
  triageStatus: FindingStatus;
  triageNote: string | null;
  triageOwner: string | null;
  triageDueAt: string | null;
  triageExpiresAt: string | null;
  triageUpdatedAt: string | null;
  triageUpdatedBy: string | null;
}

export interface PersistedScanStepDto {
  stepId: string;
  checkId: string;
  status: string;
  startedAt: string | null;
  finishedAt: string | null;
  evidenceFile: string | null;
  findingCount: number;
  message: string | null;
}

export interface PersistedScanRunProgress {
  scanRunId: string;
  status: ScanStatus | "unknown";
  gateResult: GateResult | "unknown";
  totalSteps: number;
  completedSteps: number;
  failedSteps: number;
  blockedSteps: number;
  findingCount: number;
  startedAt: string | null;
  finishedAt: string | null;
  updatedAt: string | null;
  events: Array<{
    type: string;
    message: string | null;
    createdAt: string;
  }>;
}

export interface ScanExecutionPlanLike {
  id: string;
  scanRunId: string;
  createdAt: string;
  evidenceRoot: string;
  blocked: boolean;
  blockedReasons: string[];
  project: {
    id: string;
    name: string;
    path: string;
    dataClassification?: string;
  };
  profile: {
    id: string;
    name: string;
    failThreshold?: string;
    timeoutSeconds?: number;
    allowActiveDast?: boolean;
    allowProductionTargets?: boolean;
  };
  steps: Array<{
    id: string;
    checkId: string;
    status: string;
    evidencePaths: string[];
  }>;
}

export interface ScanStepExecutionResultLike {
  stepId: string;
  checkId: string;
  status: string;
  startedAt: string;
  finishedAt: string;
  evidencePath: string;
  findings: Finding[];
  message: string;
}

export interface ScanExecutionResultLike {
  scanRunId: string;
  status: "completed" | "failed";
  startedAt: string;
  finishedAt: string;
  evidenceRoot: string;
  stepResults: ScanStepExecutionResultLike[];
  findings: Finding[];
  gate: {
    result: GateResult;
    blockingReasons: string[];
    summary: SeveritySummary;
  };
}

export interface ScanReportPathSet {
  executionResult?: string;
  json?: string;
  markdown?: string;
  centralEnvelope?: string;
  sarif?: string;
  centralTelemetryDelivery?: string;
  defectDojoDelivery?: string;
}

export interface FindingTriageUpdate {
  status: FindingStatus;
  note?: string | null;
  owner?: string | null;
  dueAt?: string | null;
  expiresAt?: string | null;
  actor?: string | null;
}

let pool: Pool | null = null;
let schemaReady = false;

export function isPersistenceEnabled(): boolean {
  return Boolean(process.env.DATABASE_URL?.trim()) && process.env.SECURITY_PREFLIGHT_DB_ENABLED !== "false";
}

export function isPersistenceRequired(): boolean {
  return process.env.SECURITY_PREFLIGHT_DB_REQUIRED === "true";
}

export async function ensurePersistenceSchema(): Promise<void> {
  await withClient(async (client) => {
    await createSchema(client);
  });
}

export async function recordQueuedScan(plan: ScanExecutionPlanLike, requestId?: string): Promise<PersistenceResult<null>> {
  return withPersistence(async (client) => {
    await upsertPlan(client, plan, "queued", {
      queuedAt: new Date().toISOString(),
      requestId
    });
    await recordScanEvent(client, plan.scanRunId, "scan.queued", "Scan run was queued.", { profileId: plan.profile.id }, requestId);
    return null;
  });
}

export async function recordRunningScan(plan: ScanExecutionPlanLike, requestId?: string): Promise<PersistenceResult<null>> {
  return withPersistence(async (client) => {
    await upsertPlan(client, plan, "running", {
      startedAt: new Date().toISOString(),
      requestId
    });
    await recordScanEvent(client, plan.scanRunId, "scan.running", "Worker started executing the scan run.", null, requestId);
    return null;
  });
}

export async function recordScanStepResult(plan: ScanExecutionPlanLike, result: ScanStepExecutionResultLike): Promise<PersistenceResult<null>> {
  return withPersistence(async (client) => {
    await upsertPlan(client, plan, "running", {});
    await upsertStepResult(client, plan.scanRunId, result);
    await upsertFindings(client, result.findings);
    await updateRunFindingCount(client, plan.scanRunId);
    await recordScanEvent(
      client,
      plan.scanRunId,
      "scan.step.completed",
      `Step ${result.checkId} finished with status ${result.status}.`,
      {
        stepId: result.stepId,
        checkId: result.checkId,
        status: result.status,
        findingCount: result.findings.length
      },
      null
    );
    return null;
  });
}

export async function recordCompletedScan(
  plan: ScanExecutionPlanLike,
  execution: ScanExecutionResultLike,
  reportPaths: ScanReportPathSet = {}
): Promise<PersistenceResult<null>> {
  return withPersistence(async (client) => {
    await upsertPlan(client, plan, execution.status, {
      startedAt: execution.startedAt,
      finishedAt: execution.finishedAt
    });

    for (const step of execution.stepResults) {
      await upsertStepResult(client, plan.scanRunId, step);
    }

    await upsertFindings(client, execution.findings);
    await client.query(
      `
        update security_preflight_scan_runs
        set status = $2,
            gate_result = $3,
            gate_blocking_reasons = $4::jsonb,
            severity_summary = $5::jsonb,
            finding_count = $6,
            evidence_files = $7::jsonb,
            evidence_flags = $8::jsonb,
            result_payload = $9::jsonb,
            started_at = $10,
            finished_at = $11,
            duration_ms = $12,
            updated_at = now()
        where id = $1
      `,
      [
        plan.scanRunId,
        execution.status,
        execution.gate.result,
        JSON.stringify(execution.gate.blockingReasons),
        JSON.stringify(execution.gate.summary),
        execution.findings.length,
        JSON.stringify(filesFromReportPaths(reportPaths)),
        JSON.stringify(evidenceFlagsFromReportPaths(reportPaths)),
        JSON.stringify(sanitizeExecutionPayload(execution)),
        execution.startedAt,
        execution.finishedAt,
        durationMs(execution.startedAt, execution.finishedAt)
      ]
    );
    await recordScanEvent(
      client,
      plan.scanRunId,
      execution.status === "completed" ? "scan.completed" : "scan.failed",
      `Scan run finished with ${execution.gate.result} gate.`,
      {
        status: execution.status,
        gateResult: execution.gate.result,
        findingCount: execution.findings.length
      },
      null
    );
    return null;
  });
}

export async function recordFailedScan(plan: ScanExecutionPlanLike, error: unknown, requestId?: string): Promise<PersistenceResult<null>> {
  return withPersistence(async (client) => {
    const message = error instanceof Error ? error.message : String(error);
    const now = new Date().toISOString();

    await upsertPlan(client, plan, "failed", {
      finishedAt: now,
      requestId
    });
    await client.query(
      `
        update security_preflight_scan_runs
        set status = 'failed',
            gate_result = 'error',
            error_message = $2,
            finished_at = coalesce(finished_at, $3),
            updated_at = now()
        where id = $1
      `,
      [plan.scanRunId, truncate(message, 2000), now]
    );
    await recordScanEvent(client, plan.scanRunId, "scan.failed", truncate(message, 2000), null, requestId);
    return null;
  });
}

export async function listPersistedScanRuns(): Promise<PersistenceResult<PersistedScanRunSummary[]>> {
  return withPersistence(async (client) => {
    const result = await client.query<ScanRunRow>(
      `
        select *
        from security_preflight_scan_runs
        order by coalesce(finished_at, started_at, queued_at, created_at) desc, id desc
        limit 250
      `
    );

    return result.rows.map(rowToSummary);
  });
}

export async function getPersistedScanRunDetail(scanRunId: string): Promise<PersistenceResult<PersistedScanRunDetail | null>> {
  return withPersistence(async (client) => {
    const runResult = await client.query<ScanRunRow>("select * from security_preflight_scan_runs where id = $1", [scanRunId]);
    const run = runResult.rows[0];

    if (!run) {
      return null;
    }

    const steps = await client.query<ScanStepRow>(
      `
        select *
        from security_preflight_scan_steps
        where scan_run_id = $1
        order by step_id asc
      `,
      [scanRunId]
    );
    const findings = await client.query<FindingRow>(
      `
        select *
        from security_preflight_findings
        where scan_run_id = $1
        order by
          case severity
            when 'critical' then 1
            when 'high' then 2
            when 'medium' then 3
            when 'low' then 4
            else 5
          end,
          title asc
      `,
      [scanRunId]
    );

    return {
      ...rowToSummary(run),
      gate: {
        result: gateResultValue(run.gate_result) ?? "unknown",
        blockingReasons: stringArray(run.gate_blocking_reasons)
      },
      findings: findings.rows.map(rowToFinding),
      steps: steps.rows.map(rowToStep)
    };
  });
}

export async function getScanRunProgress(scanRunId: string): Promise<PersistenceResult<PersistedScanRunProgress | null>> {
  return withPersistence(async (client) => {
    const runResult = await client.query<ScanRunRow>("select * from security_preflight_scan_runs where id = $1", [scanRunId]);
    const run = runResult.rows[0];

    if (!run) {
      return null;
    }

    const counts = await client.query<{
      total_steps: string;
      completed_steps: string;
      failed_steps: string;
      blocked_steps: string;
    }>(
      `
        select
          count(*)::text as total_steps,
          count(*) filter (where status in ('passed', 'failed', 'skipped', 'blocked', 'error'))::text as completed_steps,
          count(*) filter (where status in ('failed', 'error'))::text as failed_steps,
          count(*) filter (where status = 'blocked')::text as blocked_steps
        from security_preflight_scan_steps
        where scan_run_id = $1
      `,
      [scanRunId]
    );
    const events = await client.query<ScanEventRow>(
      `
        select event_type, message, created_at
        from security_preflight_scan_events
        where scan_run_id = $1
        order by created_at desc, id desc
        limit 20
      `,
      [scanRunId]
    );
    const countRow = counts.rows[0];
    const totalStepsFromPlan = arrayLength(jsonValue(run.plan_payload, "steps"));

    return {
      scanRunId,
      status: scanStatusValue(run.status) ?? "unknown",
      gateResult: gateResultValue(run.gate_result) ?? "unknown",
      totalSteps: numberFromPg(countRow?.total_steps) || totalStepsFromPlan,
      completedSteps: numberFromPg(countRow?.completed_steps),
      failedSteps: numberFromPg(countRow?.failed_steps),
      blockedSteps: numberFromPg(countRow?.blocked_steps),
      findingCount: run.finding_count ?? 0,
      startedAt: isoOrNull(run.started_at),
      finishedAt: isoOrNull(run.finished_at),
      updatedAt: isoOrNull(run.updated_at),
      events: events.rows.map((event) => ({
        type: event.event_type,
        message: event.message,
        createdAt: isoOrNull(event.created_at) ?? new Date().toISOString()
      }))
    };
  });
}

export async function updateFindingTriage(
  scanRunId: string,
  findingId: string,
  input: FindingTriageUpdate
): Promise<PersistenceResult<PersistedFindingDto | null>> {
  return withPersistence(async (client) => {
    const actor = input.actor?.trim() || "security-preflight";
    const result = await client.query<FindingRow>(
      `
        update security_preflight_findings
        set status = $3,
            triage_status = $3,
            triage_note = $4,
            triage_owner = $5,
            triage_due_at = $6,
            triage_expires_at = $7,
            triage_updated_at = now(),
            triage_updated_by = $8,
            updated_at = now()
        where scan_run_id = $1 and finding_id = $2
        returning *
      `,
      [
        scanRunId,
        findingId,
        input.status,
        nullableText(input.note),
        nullableText(input.owner),
        nullableText(input.dueAt),
        nullableText(input.expiresAt),
        actor
      ]
    );
    const row = result.rows[0];

    if (!row) {
      return null;
    }

    await client.query(
      `
        insert into security_preflight_finding_events (
          scan_run_id,
          finding_id,
          event_type,
          status,
          note,
          actor,
          payload
        )
        values ($1, $2, 'finding.triage.updated', $3, $4, $5, $6::jsonb)
      `,
      [
        scanRunId,
        findingId,
        input.status,
        nullableText(input.note),
        actor,
        JSON.stringify({
          owner: nullableText(input.owner),
          dueAt: nullableText(input.dueAt),
          expiresAt: nullableText(input.expiresAt)
        })
      ]
    );
    await recordScanEvent(
      client,
      scanRunId,
      "finding.triage.updated",
      `Finding ${findingId} triage changed to ${input.status}.`,
      { findingId, status: input.status },
      null
    );

    return rowToFinding(row);
  });
}

async function withPersistence<T>(operation: (client: PoolClient) => Promise<T>): Promise<PersistenceResult<T>> {
  if (!isPersistenceEnabled()) {
    return {
      ok: false,
      status: "disabled",
      message: "PostgreSQL persistence is disabled or DATABASE_URL is not configured."
    };
  }

  try {
    const data = await withClient(operation);
    return {
      ok: true,
      status: "ok",
      data
    };
  } catch (error) {
    if (isPersistenceRequired()) {
      throw error;
    }

    return {
      ok: false,
      status: "unavailable",
      message: error instanceof Error ? error.message : String(error)
    };
  }
}

async function withClient<T>(operation: (client: PoolClient) => Promise<T>): Promise<T> {
  if (!isPersistenceEnabled()) {
    throw new Error("PostgreSQL persistence is disabled or DATABASE_URL is not configured.");
  }

  const client = await getPool().connect();

  try {
    if (!schemaReady) {
      await createSchema(client);
      schemaReady = true;
    }

    return await operation(client);
  } finally {
    client.release();
  }
}

function getPool(): Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      application_name: process.env.SECURITY_PREFLIGHT_DB_APPLICATION_NAME ?? "security-preflight",
      max: numberFromEnv("SECURITY_PREFLIGHT_DB_POOL_MAX", 8),
      idleTimeoutMillis: numberFromEnv("SECURITY_PREFLIGHT_DB_IDLE_TIMEOUT_MS", 30_000),
      connectionTimeoutMillis: numberFromEnv("SECURITY_PREFLIGHT_DB_CONNECT_TIMEOUT_MS", 5_000)
    });
  }

  return pool;
}

async function createSchema(client: PoolClient): Promise<void> {
  await client.query(`
    create table if not exists security_preflight_scan_runs (
      id text primary key,
      plan_id text,
      status text not null,
      gate_result text not null default 'warning',
      project_id text not null,
      project_name text not null,
      project_data_classification text not null,
      profile_id text not null,
      profile_name text not null,
      created_at timestamptz not null,
      queued_at timestamptz,
      started_at timestamptz,
      finished_at timestamptz,
      duration_ms integer,
      evidence_root text not null,
      severity_summary jsonb not null default '{"critical":0,"high":0,"medium":0,"low":0,"info":0}'::jsonb,
      finding_count integer not null default 0,
      evidence_files jsonb not null default '[]'::jsonb,
      evidence_flags jsonb not null default '{}'::jsonb,
      gate_blocking_reasons jsonb not null default '[]'::jsonb,
      error_message text,
      plan_payload jsonb,
      result_payload jsonb,
      updated_at timestamptz not null default now()
    )
  `);
  await client.query(`
    create table if not exists security_preflight_scan_steps (
      scan_run_id text not null references security_preflight_scan_runs(id) on delete cascade,
      step_id text not null,
      check_id text not null,
      status text not null,
      started_at timestamptz,
      finished_at timestamptz,
      evidence_path text,
      evidence_file text,
      finding_count integer not null default 0,
      message text,
      payload jsonb,
      updated_at timestamptz not null default now(),
      primary key (scan_run_id, step_id)
    )
  `);
  await client.query(`
    create table if not exists security_preflight_findings (
      scan_run_id text not null references security_preflight_scan_runs(id) on delete cascade,
      finding_id text not null,
      tool text not null,
      type text not null,
      severity text not null,
      title text not null,
      description text,
      evidence_reference text,
      file_path text,
      line_number integer,
      endpoint text,
      cwe text,
      cve text,
      owasp text,
      recommendation text not null,
      status text not null,
      fingerprint text not null,
      raw_payload jsonb,
      triage_status text not null default 'open',
      triage_note text,
      triage_owner text,
      triage_due_at timestamptz,
      triage_expires_at timestamptz,
      triage_updated_at timestamptz,
      triage_updated_by text,
      first_seen_at timestamptz not null default now(),
      last_seen_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      primary key (scan_run_id, finding_id)
    )
  `);
  await client.query(`
    create table if not exists security_preflight_scan_events (
      id bigserial primary key,
      scan_run_id text not null references security_preflight_scan_runs(id) on delete cascade,
      event_type text not null,
      message text,
      payload jsonb,
      request_id text,
      created_at timestamptz not null default now()
    )
  `);
  await client.query(`
    create table if not exists security_preflight_finding_events (
      id bigserial primary key,
      scan_run_id text not null references security_preflight_scan_runs(id) on delete cascade,
      finding_id text not null,
      event_type text not null,
      status text,
      note text,
      actor text,
      payload jsonb,
      created_at timestamptz not null default now()
    )
  `);
  await client.query("create index if not exists idx_security_preflight_scan_runs_project on security_preflight_scan_runs(project_id)");
  await client.query("create index if not exists idx_security_preflight_scan_runs_status on security_preflight_scan_runs(status)");
  await client.query("create index if not exists idx_security_preflight_findings_scan_severity on security_preflight_findings(scan_run_id, severity)");
  await client.query("create index if not exists idx_security_preflight_scan_events_run_created on security_preflight_scan_events(scan_run_id, created_at desc)");
}

async function upsertPlan(
  client: PoolClient,
  plan: ScanExecutionPlanLike,
  status: ScanStatus,
  options: {
    queuedAt?: string;
    startedAt?: string;
    finishedAt?: string;
    requestId?: string;
  }
): Promise<void> {
  await client.query(
    `
      insert into security_preflight_scan_runs (
        id,
        plan_id,
        status,
        gate_result,
        project_id,
        project_name,
        project_data_classification,
        profile_id,
        profile_name,
        created_at,
        queued_at,
        started_at,
        finished_at,
        duration_ms,
        evidence_root,
        gate_blocking_reasons,
        plan_payload,
        updated_at
      )
      values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb, $17::jsonb, now())
      on conflict (id) do update
      set status = $3,
          project_id = $5,
          project_name = $6,
          project_data_classification = $7,
          profile_id = $8,
          profile_name = $9,
          queued_at = coalesce(security_preflight_scan_runs.queued_at, excluded.queued_at),
          started_at = coalesce(excluded.started_at, security_preflight_scan_runs.started_at),
          finished_at = coalesce(excluded.finished_at, security_preflight_scan_runs.finished_at),
          duration_ms = coalesce(excluded.duration_ms, security_preflight_scan_runs.duration_ms),
          evidence_root = excluded.evidence_root,
          gate_blocking_reasons = excluded.gate_blocking_reasons,
          plan_payload = excluded.plan_payload,
          updated_at = now()
    `,
    [
      plan.scanRunId,
      plan.id,
      status,
      plan.blocked ? "error" : "warning",
      plan.project.id,
      plan.project.name,
      plan.project.dataClassification ?? "internal",
      plan.profile.id,
      plan.profile.name,
      plan.createdAt,
      options.queuedAt ?? null,
      options.startedAt ?? null,
      options.finishedAt ?? null,
      options.startedAt && options.finishedAt ? durationMs(options.startedAt, options.finishedAt) : null,
      plan.evidenceRoot,
      JSON.stringify(plan.blockedReasons),
      JSON.stringify(sanitizePlanPayload(plan))
    ]
  );

  for (const step of plan.steps) {
    await client.query(
      `
        insert into security_preflight_scan_steps (
          scan_run_id,
          step_id,
          check_id,
          status,
          evidence_path,
          evidence_file,
          payload
        )
        values ($1, $2, $3, $4, $5, $6, $7::jsonb)
        on conflict (scan_run_id, step_id) do update
        set check_id = excluded.check_id,
            evidence_path = coalesce(security_preflight_scan_steps.evidence_path, excluded.evidence_path),
            evidence_file = coalesce(security_preflight_scan_steps.evidence_file, excluded.evidence_file),
            payload = coalesce(security_preflight_scan_steps.payload, excluded.payload),
            updated_at = now()
      `,
      [
        plan.scanRunId,
        step.id,
        step.checkId,
        step.status === "blocked" ? "blocked" : "queued",
        step.evidencePaths[0] ?? null,
        step.evidencePaths[0] ? path.basename(step.evidencePaths[0]) : null,
        JSON.stringify({
          plannedStatus: step.status,
          evidenceFiles: step.evidencePaths.map((evidencePath) => path.basename(evidencePath))
        })
      ]
    );
  }
}

async function upsertStepResult(client: PoolClient, scanRunId: string, result: ScanStepExecutionResultLike): Promise<void> {
  await client.query(
    `
      insert into security_preflight_scan_steps (
        scan_run_id,
        step_id,
        check_id,
        status,
        started_at,
        finished_at,
        evidence_path,
        evidence_file,
        finding_count,
        message,
        payload,
        updated_at
      )
      values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, now())
      on conflict (scan_run_id, step_id) do update
      set check_id = excluded.check_id,
          status = excluded.status,
          started_at = excluded.started_at,
          finished_at = excluded.finished_at,
          evidence_path = excluded.evidence_path,
          evidence_file = excluded.evidence_file,
          finding_count = excluded.finding_count,
          message = excluded.message,
          payload = excluded.payload,
          updated_at = now()
    `,
    [
      scanRunId,
      result.stepId,
      result.checkId,
      result.status,
      result.startedAt,
      result.finishedAt,
      result.evidencePath,
      path.basename(result.evidencePath),
      result.findings.length,
      truncate(result.message, 4000),
      JSON.stringify(sanitizeStepPayload(result))
    ]
  );
}

async function upsertFindings(client: PoolClient, findings: Finding[]): Promise<void> {
  for (const finding of findings) {
    await client.query(
      `
        insert into security_preflight_findings (
          scan_run_id,
          finding_id,
          tool,
          type,
          severity,
          title,
          description,
          evidence_reference,
          file_path,
          line_number,
          endpoint,
          cwe,
          cve,
          owasp,
          recommendation,
          status,
          fingerprint,
          raw_payload,
          triage_status,
          last_seen_at,
          updated_at
        )
        values ($1, $2, $3, $4, $5, $6, $7, null, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::jsonb, $15, now(), now())
        on conflict (scan_run_id, finding_id) do update
        set tool = excluded.tool,
            type = excluded.type,
            severity = excluded.severity,
            title = excluded.title,
            description = excluded.description,
            file_path = excluded.file_path,
            line_number = excluded.line_number,
            endpoint = excluded.endpoint,
            cwe = excluded.cwe,
            cve = excluded.cve,
            owasp = excluded.owasp,
            recommendation = excluded.recommendation,
            fingerprint = excluded.fingerprint,
            raw_payload = excluded.raw_payload,
            last_seen_at = now(),
            updated_at = now()
      `,
      [
        finding.scanRunId,
        finding.id,
        finding.tool,
        finding.type,
        finding.severity,
        truncate(finding.title, 1000),
        truncate(finding.description, 4000),
        nullableText(finding.filePath),
        finding.line,
        nullableText(finding.endpoint),
        nullableText(finding.cwe),
        nullableText(finding.cve),
        nullableText(finding.owasp),
        truncate(finding.recommendation, 4000),
        finding.status,
        finding.fingerprint,
        JSON.stringify(sanitizeFindingPayload(finding))
      ]
    );
  }
}

async function updateRunFindingCount(client: PoolClient, scanRunId: string): Promise<void> {
  const summary = await client.query<SeveritySummaryRow>(
    `
      select
        count(*)::int as total,
        count(*) filter (where severity = 'critical')::int as critical,
        count(*) filter (where severity = 'high')::int as high,
        count(*) filter (where severity = 'medium')::int as medium,
        count(*) filter (where severity = 'low')::int as low,
        count(*) filter (where severity = 'info')::int as info
      from security_preflight_findings
      where scan_run_id = $1
    `,
    [scanRunId]
  );
  const row = summary.rows[0];

  await client.query(
    `
      update security_preflight_scan_runs
      set finding_count = $2,
          severity_summary = $3::jsonb,
          updated_at = now()
      where id = $1
    `,
    [
      scanRunId,
      row?.total ?? 0,
      JSON.stringify({
        critical: row?.critical ?? 0,
        high: row?.high ?? 0,
        medium: row?.medium ?? 0,
        low: row?.low ?? 0,
        info: row?.info ?? 0
      })
    ]
  );
}

async function recordScanEvent(
  client: PoolClient,
  scanRunId: string,
  eventType: string,
  message: string | null,
  payload: Record<string, unknown> | null,
  requestId: string | null | undefined
): Promise<void> {
  await client.query(
    `
      insert into security_preflight_scan_events (
        scan_run_id,
        event_type,
        message,
        payload,
        request_id
      )
      values ($1, $2, $3, $4::jsonb, $5)
    `,
    [scanRunId, eventType, message ? truncate(message, 4000) : null, payload ? JSON.stringify(payload) : null, requestId ?? null]
  );
}

function rowToSummary(row: ScanRunRow): PersistedScanRunSummary {
  const evidenceFlags = recordFromJson(row.evidence_flags);
  const evidenceFiles = stringArray(row.evidence_files);

  return {
    id: row.id,
    status: scanStatusValue(row.status) ?? "unknown",
    gateResult: gateResultValue(row.gate_result) ?? "unknown",
    project: {
      id: row.project_id,
      name: row.project_name,
      dataClassification: row.project_data_classification
    },
    profile: {
      id: row.profile_id,
      name: row.profile_name
    },
    startedAt: isoOrNull(row.started_at),
    finishedAt: isoOrNull(row.finished_at),
    durationMs: row.duration_ms,
    findingCount: row.finding_count ?? 0,
    severitySummary: severitySummaryFromJson(row.severity_summary),
    evidence: {
      root: row.evidence_root,
      files: evidenceFiles,
      hasExecutionResult: booleanValue(evidenceFlags.hasExecutionResult),
      hasJsonReport: booleanValue(evidenceFlags.hasJsonReport),
      hasMarkdownReport: booleanValue(evidenceFlags.hasMarkdownReport),
      hasCentralEnvelope: booleanValue(evidenceFlags.hasCentralEnvelope),
      hasSarifReport: booleanValue(evidenceFlags.hasSarifReport),
      hasCentralTelemetryDelivery: booleanValue(evidenceFlags.hasCentralTelemetryDelivery),
      hasDefectDojoDelivery: booleanValue(evidenceFlags.hasDefectDojoDelivery)
    }
  };
}

function rowToStep(row: ScanStepRow): PersistedScanStepDto {
  return {
    stepId: row.step_id,
    checkId: row.check_id,
    status: row.status,
    startedAt: isoOrNull(row.started_at),
    finishedAt: isoOrNull(row.finished_at),
    evidenceFile: row.evidence_file,
    findingCount: row.finding_count ?? 0,
    message: row.message
  };
}

function rowToFinding(row: FindingRow): PersistedFindingDto {
  return {
    id: row.finding_id,
    tool: row.tool,
    type: row.type,
    severity: row.severity,
    title: row.title,
    filePath: row.file_path,
    line: row.line_number,
    endpoint: row.endpoint,
    status: row.status,
    recommendation: row.recommendation,
    triageStatus: findingStatusValue(row.triage_status) ?? "open",
    triageNote: row.triage_note,
    triageOwner: row.triage_owner,
    triageDueAt: isoOrNull(row.triage_due_at),
    triageExpiresAt: isoOrNull(row.triage_expires_at),
    triageUpdatedAt: isoOrNull(row.triage_updated_at),
    triageUpdatedBy: row.triage_updated_by
  };
}

function filesFromReportPaths(paths: ScanReportPathSet): string[] {
  return [
    paths.executionResult,
    paths.json,
    paths.markdown,
    paths.centralEnvelope,
    paths.sarif,
    paths.centralTelemetryDelivery,
    paths.defectDojoDelivery
  ]
    .filter((value): value is string => Boolean(value))
    .map((value) => path.basename(value))
    .sort();
}

function evidenceFlagsFromReportPaths(paths: ScanReportPathSet): PersistedScanRunSummary["evidence"] extends infer Evidence
  ? Evidence extends { hasExecutionResult: boolean }
    ? Omit<Evidence, "root" | "files">
    : never
  : never {
  return {
    hasExecutionResult: Boolean(paths.executionResult),
    hasJsonReport: Boolean(paths.json),
    hasMarkdownReport: Boolean(paths.markdown),
    hasCentralEnvelope: Boolean(paths.centralEnvelope),
    hasSarifReport: Boolean(paths.sarif),
    hasCentralTelemetryDelivery: Boolean(paths.centralTelemetryDelivery),
    hasDefectDojoDelivery: Boolean(paths.defectDojoDelivery)
  };
}

function sanitizePlanPayload(plan: ScanExecutionPlanLike): Record<string, unknown> {
  return {
    id: plan.id,
    scanRunId: plan.scanRunId,
    createdAt: plan.createdAt,
    blocked: plan.blocked,
    blockedReasons: plan.blockedReasons,
    project: {
      id: plan.project.id,
      name: plan.project.name,
      path: plan.project.path,
      dataClassification: plan.project.dataClassification ?? "internal"
    },
    profile: plan.profile,
    evidenceRoot: plan.evidenceRoot,
    steps: plan.steps.map((step) => ({
      id: step.id,
      checkId: step.checkId,
      status: step.status,
      evidenceFiles: step.evidencePaths.map((evidencePath) => path.basename(evidencePath))
    }))
  };
}

function sanitizeStepPayload(result: ScanStepExecutionResultLike): Record<string, unknown> {
  return {
    stepId: result.stepId,
    checkId: result.checkId,
    status: result.status,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    evidenceFile: path.basename(result.evidencePath),
    findingIds: result.findings.map((finding) => finding.id),
    findingCount: result.findings.length,
    message: truncate(result.message, 4000)
  };
}

function sanitizeExecutionPayload(execution: ScanExecutionResultLike): Record<string, unknown> {
  return {
    scanRunId: execution.scanRunId,
    status: execution.status,
    startedAt: execution.startedAt,
    finishedAt: execution.finishedAt,
    evidenceRoot: execution.evidenceRoot,
    gate: execution.gate,
    findingIds: execution.findings.map((finding) => finding.id),
    stepResults: execution.stepResults.map((step) => sanitizeStepPayload(step))
  };
}

function sanitizeFindingPayload(finding: Finding): Record<string, unknown> {
  return {
    id: finding.id,
    scanRunId: finding.scanRunId,
    tool: finding.tool,
    type: finding.type,
    severity: finding.severity,
    title: truncate(finding.title, 1000),
    description: truncate(finding.description, 4000),
    filePath: finding.filePath,
    line: finding.line,
    endpoint: finding.endpoint,
    cwe: finding.cwe,
    cve: finding.cve,
    owasp: finding.owasp,
    recommendation: truncate(finding.recommendation, 4000),
    status: finding.status,
    fingerprint: finding.fingerprint
  };
}

function isoOrNull(value: Date | string | null | undefined): string | null {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString();

  return value;
}

function durationMs(startedAt: string | null | undefined, finishedAt: string | null | undefined): number | null {
  const start = startedAt ? Date.parse(startedAt) : 0;
  const end = finishedAt ? Date.parse(finishedAt) : 0;

  return start > 0 && end > 0 && end >= start ? end - start : null;
}

function severitySummaryFromJson(value: unknown): SeveritySummary {
  const record = recordFromJson(value);

  return {
    critical: numberValue(record.critical),
    high: numberValue(record.high),
    medium: numberValue(record.medium),
    low: numberValue(record.low),
    info: numberValue(record.info)
  };
}

function jsonValue(value: unknown, key: string): unknown {
  return recordFromJson(value)[key];
}

function recordFromJson(value: unknown): Record<string, unknown> {
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  }

  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function stringArray(value: unknown): string[] {
  if (typeof value === "string") {
    try {
      return stringArray(JSON.parse(value) as unknown);
    } catch {
      return [];
    }
  }

  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function arrayLength(value: unknown): number {
  return Array.isArray(value) ? value.length : 0;
}

function nullableText(value: string | null | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed : null;
}

function truncate(value: string, maxLength: number): string {
  return value.length <= maxLength ? value : value.slice(0, maxLength);
}

function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function numberFromPg(value: string | number | null | undefined): number {
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }

  return 0;
}

function numberFromEnv(key: string, fallback: number): number {
  const parsed = Number(process.env[key]);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function booleanValue(value: unknown): boolean {
  return value === true;
}

function scanStatusValue(value: unknown): ScanStatus | null {
  return value === "queued" || value === "running" || value === "completed" || value === "failed" || value === "cancelled" ? value : null;
}

function gateResultValue(value: unknown): GateResult | null {
  return value === "pass" || value === "warning" || value === "fail" || value === "error" ? value : null;
}

function findingStatusValue(value: unknown): FindingStatus | null {
  return value === "open" || value === "accepted" || value === "false-positive" || value === "fixed" || value === "suppressed" ? value : null;
}

interface ScanRunRow {
  id: string;
  status: string;
  gate_result: string;
  project_id: string;
  project_name: string;
  project_data_classification: string;
  profile_id: string;
  profile_name: string;
  started_at: Date | string | null;
  finished_at: Date | string | null;
  duration_ms: number | null;
  finding_count: number | null;
  severity_summary: unknown;
  evidence_root: string;
  evidence_files: unknown;
  evidence_flags: unknown;
  gate_blocking_reasons: unknown;
  plan_payload: unknown;
  updated_at: Date | string | null;
}

interface ScanStepRow {
  step_id: string;
  check_id: string;
  status: string;
  started_at: Date | string | null;
  finished_at: Date | string | null;
  evidence_file: string | null;
  finding_count: number | null;
  message: string | null;
}

interface FindingRow {
  finding_id: string;
  tool: string;
  type: string;
  severity: string;
  title: string;
  file_path: string | null;
  line_number: number | null;
  endpoint: string | null;
  status: string;
  recommendation: string;
  triage_status: string;
  triage_note: string | null;
  triage_owner: string | null;
  triage_due_at: Date | string | null;
  triage_expires_at: Date | string | null;
  triage_updated_at: Date | string | null;
  triage_updated_by: string | null;
}

interface SeveritySummaryRow {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface ScanEventRow {
  event_type: string;
  message: string | null;
  created_at: Date | string;
}
