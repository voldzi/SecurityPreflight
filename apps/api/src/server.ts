import { createHash, randomUUID } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import cors from "@fastify/cors";
import Fastify, { type FastifyInstance } from "fastify";
import { z } from "zod";
import { Queue } from "bullmq";
import { defaultScanProfiles, requiredScannerTools, type FindingStatus, type GateResult, type ScanStatus, type SeveritySummary } from "@security-preflight/core";
import { buildScanExecutionPlan, type ScanExecutionPlan, runToolchainDoctor } from "@security-preflight/scanners";
import {
  getPersistedScanRunDetail,
  getScanRunProgress,
  listPersistedScanRuns,
  recordQueuedScan,
  updateFindingTriage,
  type PersistedScanRunProgress
} from "@security-preflight/persistence";
import { AkbIntegrationError, askAkb, getAkbIntegrationStatus } from "./akb.js";
import {
  authenticateSecurityPreflightRequest,
  getAuthStatus,
  isPublicRoute,
  type SecurityPreflightAuthContext
} from "./auth.js";
import {
  createProject,
  deleteProject,
  getProject,
  listProjects,
  projectRegistryPath,
  ProjectRegistryError,
  updateProject
} from "./projects.js";
import { buildScanRunReportExport, type ScanRunExportFormat } from "./report-export.js";
import { applySecurityHeaders } from "./security-headers.js";

export interface CreateServerOptions {
  logger?: boolean;
  scanQueue?: ScanQueue;
}

declare module "fastify" {
  interface FastifyRequest {
    authContext?: SecurityPreflightAuthContext | null;
  }
}

export interface ScanQueue {
  add(name: string, data: unknown, options?: Record<string, unknown>): Promise<{ id?: string | number }>;
}

interface ScanRunSummaryDto {
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

interface ScanRunDetailDto extends ScanRunSummaryDto {
  gate: {
    result: GateResult | "unknown";
    blockingReasons: string[];
  };
  findings: Array<{
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
  }>;
  steps: Array<{
    stepId: string;
    checkId: string;
    status: string;
    startedAt: string | null;
    finishedAt: string | null;
    evidenceFile: string | null;
    findingCount: number;
    message: string | null;
  }>;
}

const dataClassificationSchema = z.enum(["public", "internal", "confidential", "sensitive", "health-data"]);
const projectIdSchema = z.string().min(1).regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{1,119}$/, "Project ID contains unsupported characters.");
const scanRunIdSchema = z.string().min(1).regex(/^[A-Za-z0-9_.:-]+$/, "Scan run ID contains unsupported characters.");
const findingIdSchema = z.string().min(1).max(240).regex(/^[A-Za-z0-9_.:-]+$/, "Finding ID contains unsupported characters.");
const reportFormatSchema = z.enum(["markdown", "json"]).default("markdown");
const triageStatusSchema = z.enum(["open", "accepted", "false-positive", "fixed", "suppressed"]);
const findingTriageRequestSchema = z.object({
  status: triageStatusSchema,
  note: z.string().max(4000).nullable().optional(),
  owner: z.string().max(240).nullable().optional(),
  dueAt: z.string().datetime().nullable().optional(),
  expiresAt: z.string().datetime().nullable().optional()
});
const projectCreateRequestSchema = z.object({
  id: projectIdSchema.optional(),
  name: z.string().min(1).max(160),
  path: z.string().min(1).max(2000),
  repositoryUrl: z.string().min(1).max(2000).nullable().optional(),
  defaultBranch: z.string().min(1).max(160).nullable().optional(),
  dataClassification: dataClassificationSchema.default("internal"),
  owner: z.string().min(1).max(160).nullable().optional()
});
const projectUpdateRequestSchema = projectCreateRequestSchema.omit({ id: true }).partial().refine((value) => Object.keys(value).length > 0, {
  message: "At least one project field must be provided."
});
const reportExportRequestSchema = z.object({
  scanRunId: scanRunIdSchema,
  format: z.enum(["PDF", "PPTX", "pdf", "pptx"]).default("PDF"),
  locale: z.enum(["cs", "en"]).default("cs"),
  template: z.string().min(1).max(120).optional()
});
const akbAskRequestSchema = z.object({
  scanRunId: scanRunIdSchema,
  question: z.string().min(3).max(2000),
  answerMode: z.string().min(1).max(120).optional(),
  responseLanguage: z.string().min(2).max(12).optional(),
  maxChunks: z.number().int().min(1).max(30).optional(),
  subject: z
    .object({
      tenantId: z.string().min(1).max(120).optional(),
      userId: z.string().min(1).max(120).optional(),
      roles: z.array(z.string().min(1).max(120)).max(30).optional(),
      classificationClearance: z.array(z.string().min(1).max(120)).max(20).optional()
    })
    .optional()
});

const scanPlanRequestSchema = z.object({
  scanRunId: z.string().min(1).optional(),
  profileId: z.string().min(1).default("fast-local"),
  reportsRoot: z.string().min(1).optional(),
  project: z.object({
    id: z.string().min(1),
    name: z.string().min(1),
    path: z.string().min(1).refine((value) => path.isAbsolute(value), {
      message: "Project path must be absolute."
    }),
    dataClassification: dataClassificationSchema.default("internal")
  }),
  dast: z
    .object({
      targetUrl: z.string().url().optional(),
      allowedHosts: z.array(z.string().min(1)).optional(),
      excludedPaths: z.array(z.string().min(1)).optional(),
      allowActiveScan: z.boolean().optional(),
      allowProductionTargets: z.boolean().optional(),
      timeoutSeconds: z.number().int().positive().optional()
    })
    .optional()
});

const resultEnvelopeSchema = z
  .object({
    schemaVersion: z.literal("security-preflight.result.v1"),
    envelopeId: z.string().min(1).optional(),
    generatedAt: z.string().datetime(),
    producer: z.object({
      name: z.string().min(1),
      version: z.string().min(1)
    }),
    project: z.object({
      id: z.string().min(1),
      name: z.string().min(1),
      dataClassification: dataClassificationSchema
    }).passthrough(),
    scanRun: z.object({
      id: z.string().min(1),
      status: z.enum(["queued", "running", "completed", "failed", "cancelled"]),
      gateResult: z.enum(["pass", "warning", "fail", "error"])
    }).passthrough(),
    profile: z.object({
      id: z.string().min(1),
      name: z.string().min(1),
      checks: z.array(z.string())
    }).passthrough(),
    gate: z.object({
      result: z.enum(["pass", "warning", "fail", "error"]),
      blockingReasons: z.array(z.string())
    }).passthrough(),
    findings: z.array(z.object({}).passthrough()),
    evidence: z.object({
      findingCount: z.number().int().min(0),
      redacted: z.literal(true)
    }).passthrough()
  })
  .passthrough();

export function createServer(options: CreateServerOptions = {}): FastifyInstance {
  let scanQueue: ScanQueue | null = options.scanQueue ?? null;
  const server = Fastify({
    logger: options.logger ?? true,
    genReqId: (request) => request.headers["x-request-id"]?.toString() ?? `req_${randomUUID()}`
  });

  server.addHook("onRequest", async (_request, reply) => {
    applySecurityHeaders(reply);
  });

  void server.register(cors, {
    origin(origin, callback) {
      callback(null, isAllowedCorsOrigin(origin));
    },
    allowedHeaders: ["content-type", "authorization", "x-request-id"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
  });

  server.addHook("preHandler", async (request, reply) => {
    if (!request.url.startsWith("/api/v1/") || isPublicRoute(request)) {
      return;
    }

    const auth = await authenticateSecurityPreflightRequest(request);

    if (!auth.ok) {
      return reply.status(auth.statusCode).send({
        error: {
          code: auth.code,
          message: auth.message,
          requestId: request.id
        }
      });
    }

    request.authContext = auth.context;
  });

  server.setErrorHandler((error, request, reply) => {
    request.log.error({ err: error }, "request failed");
    const appError = error as { statusCode?: number; message?: string };
    const statusCode = appError.statusCode && appError.statusCode >= 400 ? appError.statusCode : 500;

    return reply.status(statusCode).send({
      error: {
        code: statusCode === 500 ? "INTERNAL_ERROR" : "REQUEST_ERROR",
        message: statusCode === 500 ? "Internal server error." : (appError.message ?? "Request failed."),
        requestId: request.id
      }
    });
  });

  server.get("/health", async () => ({
    status: "ok",
    service: "security-preflight-api",
    version: process.env.npm_package_version ?? "0.1.0",
    timestamp: new Date().toISOString()
  }));

  server.get("/ready", async (request, reply) => {
    const required = {
      databaseUrl: Boolean(process.env.DATABASE_URL),
      redisUrl: Boolean(process.env.REDIS_URL),
      reportsPath: Boolean(process.env.REPORTS_PATH)
    };

    const ready = Object.values(required).every(Boolean);

    if (!ready) {
      return reply.status(503).send({
        error: {
          code: "SERVICE_NOT_READY",
          message: "Required local dependencies are not configured.",
          details: [required],
          requestId: request.id
        }
      });
    }

    return {
      status: "ok",
      service: "security-preflight-api",
      version: process.env.npm_package_version ?? "0.1.0",
      timestamp: new Date().toISOString()
    };
  });

  server.get("/api/v1/auth/status", async () => ({
    data: getAuthStatus()
  }));

  server.get("/api/v1/projects", async () => {
    const data = await listProjects();

    return {
      data,
      meta: {
        total: data.length,
        registryPath: projectRegistryPath()
      }
    };
  });

  server.post("/api/v1/projects", async (request, reply) => {
    const parsed = projectCreateRequestSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid project registration request.",
          details: [parsed.error.flatten()],
          requestId: request.id
        }
      });
    }

    try {
      const project = await createProject(parsed.data);

      return reply.status(201).send({
        data: project
      });
    } catch (error) {
      if (error instanceof ProjectRegistryError) {
        return reply.status(error.statusCode).send({
          error: {
            code: error.code,
            message: error.message,
            details: error.details,
            requestId: request.id
          }
        });
      }

      throw error;
    }
  });

  server.get("/api/v1/projects/:projectId", async (request, reply) => {
    const parsed = projectIdSchema.safeParse((request.params as { projectId?: string }).projectId);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid project ID.",
          details: [parsed.error.flatten()],
          requestId: request.id
        }
      });
    }

    const project = await getProject(parsed.data);

    if (!project) {
      return reply.status(404).send({
        error: {
          code: "PROJECT_NOT_FOUND",
          message: "Registered project was not found.",
          requestId: request.id
        }
      });
    }

    return {
      data: project
    };
  });

  server.patch("/api/v1/projects/:projectId", async (request, reply) => {
    const projectId = projectIdSchema.safeParse((request.params as { projectId?: string }).projectId);
    const body = projectUpdateRequestSchema.safeParse(request.body);

    if (!projectId.success || !body.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid project update request.",
          details: [projectId.success ? null : projectId.error.flatten(), body.success ? null : body.error.flatten()].filter(Boolean),
          requestId: request.id
        }
      });
    }

    try {
      const project = await updateProject(projectId.data, body.data);

      return {
        data: project
      };
    } catch (error) {
      if (error instanceof ProjectRegistryError) {
        return reply.status(error.statusCode).send({
          error: {
            code: error.code,
            message: error.message,
            details: error.details,
            requestId: request.id
          }
        });
      }

      throw error;
    }
  });

  server.delete("/api/v1/projects/:projectId", async (request, reply) => {
    const parsed = projectIdSchema.safeParse((request.params as { projectId?: string }).projectId);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid project ID.",
          details: [parsed.error.flatten()],
          requestId: request.id
        }
      });
    }

    const deleted = await deleteProject(parsed.data);

    if (!deleted) {
      return reply.status(404).send({
        error: {
          code: "PROJECT_NOT_FOUND",
          message: "Registered project was not found.",
          requestId: request.id
        }
      });
    }

    return reply.status(204).send();
  });

  server.get("/api/v1/scan-profiles", async () => ({
    data: defaultScanProfiles
  }));

  server.get("/api/v1/scans/runs", async () => {
    const data = await listScanRuns();

    return {
      data,
      meta: {
        total: data.length,
        reportsPath: getReportsPath()
      }
    };
  });

  server.get("/api/v1/scans/runs/:scanRunId", async (request, reply) => {
    const parsed = scanRunIdSchema.safeParse((request.params as { scanRunId?: string }).scanRunId);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid scan run ID.",
          details: [parsed.error.flatten()],
          requestId: request.id
        }
      });
    }

    const detail = await getScanRunDetail(parsed.data);

    if (!detail) {
      return reply.status(404).send({
        error: {
          code: "SCAN_RUN_NOT_FOUND",
          message: "Scan run evidence was not found.",
          requestId: request.id
        }
      });
    }

    return {
      data: detail
    };
  });

  server.get("/api/v1/scans/runs/:scanRunId/progress", async (request, reply) => {
    const parsed = scanRunIdSchema.safeParse((request.params as { scanRunId?: string }).scanRunId);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid scan run ID.",
          details: [parsed.error.flatten()],
          requestId: request.id
        }
      });
    }

    const persisted = await getScanRunProgress(parsed.data);

    if (persisted.ok && persisted.data) {
      return {
        data: persisted.data
      };
    }

    const detail = await getEvidenceScanRunDetail(parsed.data);

    if (!detail) {
      return reply.status(404).send({
        error: {
          code: "SCAN_RUN_NOT_FOUND",
          message: "Scan run progress was not found.",
          requestId: request.id
        }
      });
    }

    return {
      data: progressFromDetail(detail)
    };
  });

  server.patch("/api/v1/scans/runs/:scanRunId/findings/:findingId/triage", async (request, reply) => {
    const scanRunId = scanRunIdSchema.safeParse((request.params as { scanRunId?: string }).scanRunId);
    const findingId = findingIdSchema.safeParse((request.params as { findingId?: string }).findingId);
    const body = findingTriageRequestSchema.safeParse(request.body);

    if (!scanRunId.success || !findingId.success || !body.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid finding triage request.",
          details: [
            scanRunId.success ? null : scanRunId.error.flatten(),
            findingId.success ? null : findingId.error.flatten(),
            body.success ? null : body.error.flatten()
          ].filter(Boolean),
          requestId: request.id
        }
      });
    }

    const result = await updateFindingTriage(scanRunId.data, findingId.data, {
      status: body.data.status,
      note: body.data.note,
      owner: body.data.owner,
      dueAt: body.data.dueAt,
      expiresAt: body.data.expiresAt,
      actor: request.authContext?.subject ?? request.authContext?.roles[0] ?? "security-preflight-api"
    });

    if (!result.ok) {
      return reply.status(503).send({
        error: {
          code: "PERSISTENCE_UNAVAILABLE",
          message: "Finding triage requires PostgreSQL persistence.",
          details: [{ status: result.status, message: result.message }],
          requestId: request.id
        }
      });
    }

    if (!result.data) {
      return reply.status(404).send({
        error: {
          code: "FINDING_NOT_FOUND",
          message: "Finding was not found in persisted scan results.",
          requestId: request.id
        }
      });
    }

    return {
      data: result.data
    };
  });

  server.get("/api/v1/scans/runs/:scanRunId/report", async (request, reply) => {
    const scanRunId = scanRunIdSchema.safeParse((request.params as { scanRunId?: string }).scanRunId);
    const format = reportFormatSchema.safeParse((request.query as { format?: string }).format ?? "markdown");

    if (!scanRunId.success || !format.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid scan report request.",
          details: [scanRunId.success ? null : scanRunId.error.flatten(), format.success ? null : format.error.flatten()].filter(Boolean),
          requestId: request.id
        }
      });
    }

    const report = await readScanRunReport(scanRunId.data, format.data);

    if (!report) {
      return reply.status(404).send({
        error: {
          code: "SCAN_REPORT_NOT_FOUND",
          message: "Scan report evidence was not found.",
          requestId: request.id
        }
      });
    }

    return {
      data: report
    };
  });

  server.post("/api/v1/reports/export", async (request, reply) => {
    const parsed = reportExportRequestSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid report export request.",
          details: [parsed.error.flatten()],
          requestId: request.id
        }
      });
    }

    const run = await getScanRunDetail(parsed.data.scanRunId);

    if (!run) {
      return reply.status(404).send({
        error: {
          code: "SCAN_RUN_NOT_FOUND",
          message: "Scan run evidence was not found.",
          requestId: request.id
        }
      });
    }

    const markdownReport = await readScanRunReport(parsed.data.scanRunId, "markdown");
    const format = parsed.data.format.toUpperCase() as ScanRunExportFormat;
    const exported = await buildScanRunReportExport({
      format,
      locale: parsed.data.locale,
      template: parsed.data.template,
      run,
      markdownReport: typeof markdownReport?.content === "string" ? markdownReport.content : undefined
    });

    return {
      data: exported
    };
  });

  server.get("/api/v1/akb/status", async (request) => ({
    data: getAkbIntegrationStatus(request.headers.authorization?.toString())
  }));

  server.post("/api/v1/akb/ai/ask", async (request, reply) => {
    const parsed = akbAskRequestSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid AKB AI request.",
          details: [parsed.error.flatten()],
          requestId: request.id
        }
      });
    }

    const run = await getScanRunDetail(parsed.data.scanRunId);

    if (!run) {
      return reply.status(404).send({
        error: {
          code: "SCAN_RUN_NOT_FOUND",
          message: "Scan run evidence was not found.",
          requestId: request.id
        }
      });
    }

    try {
      const result = await askAkb({
        question: parsed.data.question,
        answerMode: parsed.data.answerMode,
        responseLanguage: parsed.data.responseLanguage,
        maxChunks: parsed.data.maxChunks,
        correlationId: request.id,
        authorization: request.headers.authorization?.toString(),
        subject: {
          tenantId: parsed.data.subject?.tenantId,
          userId: request.authContext?.subject ?? parsed.data.subject?.userId,
          roles: request.authContext?.roles ?? parsed.data.subject?.roles,
          classificationClearance: parsed.data.subject?.classificationClearance
        },
        run
      });

      return {
        data: result
      };
    } catch (error) {
      if (error instanceof AkbIntegrationError) {
        return reply.status(error.statusCode).send({
          error: {
            code: error.code,
            message: error.message,
            details: error.details.length ? error.details : undefined,
            requestId: request.id
          }
        });
      }

      throw error;
    }
  });

  server.get("/api/v1/toolchain/requirements", async () => ({
    data: requiredScannerTools,
    meta: {
      total: requiredScannerTools.length,
      healthcareRequired: requiredScannerTools.filter((tool) => tool.requiredForHealthcare).length
    }
  }));

  server.post("/api/v1/scans/plan", async (request, reply) => {
    const result = buildPlanFromRequest(request.body, request.id);

    if ("error" in result) {
      return reply.status(result.statusCode).send(result.error);
    }

    return result.plan;
  });

  server.post("/api/v1/scans/queue", async (request, reply) => {
    const result = buildPlanFromRequest(request.body, request.id);

    if ("error" in result) {
      return reply.status(result.statusCode).send(result.error);
    }

    if (result.plan.blocked) {
      return reply.status(409).send({
        error: {
          code: "SCAN_PLAN_BLOCKED",
          message: "Scan plan is blocked by guardrails and cannot be queued.",
          details: [result.plan],
          requestId: request.id
        }
      });
    }

    scanQueue ??= new Queue(process.env.SCAN_QUEUE_NAME ?? "security-preflight-scans", {
      connection: {
        url: process.env.REDIS_URL ?? "redis://localhost:6379/0"
      }
    });

    const job = await scanQueue.add(
      "scan.execute",
      {
        plan: result.plan,
        requestId: request.id,
        queuedAt: new Date().toISOString()
      },
      {
        jobId: result.plan.scanRunId,
        removeOnComplete: 100,
        removeOnFail: 100
      }
    );
    await recordQueuedScan(result.plan, request.id);

    return reply.status(202).send({
      data: {
        jobId: String(job.id ?? result.plan.scanRunId),
        scanRunId: result.plan.scanRunId,
        status: "queued",
        plan: result.plan
      }
    });
  });

  server.get("/api/v1/toolchain/doctor", async () => runToolchainDoctor());

  server.post("/api/v1/results/ingest", async (request, reply) => {
    const parsed = resultEnvelopeSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid central result envelope.",
          details: [parsed.error.flatten()],
          requestId: request.id
        }
      });
    }

    const material = JSON.stringify({
      projectId: parsed.data.project.id,
      scanRunId: parsed.data.scanRun.id,
      generatedAt: parsed.data.generatedAt,
      gate: parsed.data.gate.result
    });
    const envelopeId = parsed.data.envelopeId ?? `spr_${createHash("sha256").update(material).digest("hex").slice(0, 24)}`;

    return reply.status(202).send({
      data: {
        status: "accepted",
        envelopeId,
        scanRunId: parsed.data.scanRun.id,
        receivedAt: new Date().toISOString()
      }
    });
  });

  return server;
}

function getReportsPath(): string {
  return path.resolve(process.env.REPORTS_PATH ?? "/reports");
}

async function listScanRuns(): Promise<ScanRunSummaryDto[]> {
  const persisted = await listPersistedScanRuns();
  const evidenceRuns = await listEvidenceScanRuns();

  if (!persisted.ok) {
    return evidenceRuns;
  }

  const persistedIds = new Set(persisted.data.map((run) => run.id));

  return [...persisted.data, ...evidenceRuns.filter((run) => !persistedIds.has(run.id))].sort(
    (left, right) => timestampValue(right.finishedAt ?? right.startedAt) - timestampValue(left.finishedAt ?? left.startedAt)
  );
}

async function listEvidenceScanRuns(): Promise<ScanRunSummaryDto[]> {
  const reportsPath = getReportsPath();
  let entries: Array<{ name: string; isDirectory(): boolean }>;

  try {
    entries = await readdir(reportsPath, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }

    throw error;
  }

  const runs = await Promise.all(
    entries
      .filter((entry) => entry.isDirectory())
      .map(async (entry) => {
        try {
          return await readScanRunSummary(entry.name);
        } catch {
          return null;
        }
      })
  );

  return runs
    .filter((run): run is ScanRunSummaryDto => run !== null)
    .sort((left, right) => timestampValue(right.finishedAt ?? right.startedAt) - timestampValue(left.finishedAt ?? left.startedAt));
}

async function getScanRunDetail(scanRunId: string): Promise<ScanRunDetailDto | null> {
  const persisted = await getPersistedScanRunDetail(scanRunId);

  if (persisted.ok && persisted.data) {
    return persisted.data;
  }

  return getEvidenceScanRunDetail(scanRunId);
}

async function getEvidenceScanRunDetail(scanRunId: string): Promise<ScanRunDetailDto | null> {
  const summary = await readScanRunSummary(scanRunId);

  if (!summary) {
    return null;
  }

  const execution = await readScanRunJson(scanRunId, "execution-result.json");
  const report = await readScanRunJson(scanRunId, "report.json");
  const executionRecord = asRecord(execution);
  const reportRecord = asRecord(report);
  const gate = recordValue(reportRecord.gate) ?? recordValue(executionRecord.gate) ?? {};
  const findings = arrayValue(reportRecord.findings ?? executionRecord.findings).map((finding) => {
    const item = asRecord(finding);

    return {
      id: stringValue(item.id) ?? "finding",
      tool: stringValue(item.tool) ?? "unknown",
      type: stringValue(item.type) ?? "unknown",
      severity: stringValue(item.severity) ?? "info",
      title: stringValue(item.title) ?? "Untitled finding",
      filePath: nullableString(item.filePath),
      line: numberValue(item.line),
      endpoint: nullableString(item.endpoint),
      status: stringValue(item.status) ?? "open",
      recommendation: stringValue(item.recommendation) ?? "Review the finding evidence.",
      triageStatus: findingStatusValue(item.status) ?? "open",
      triageNote: null,
      triageOwner: null,
      triageDueAt: null,
      triageExpiresAt: null,
      triageUpdatedAt: null,
      triageUpdatedBy: null
    };
  });
  const steps = arrayValue(executionRecord.stepResults).map((step) => {
    const item = asRecord(step);
    const evidencePath = nullableString(item.evidencePath);

    return {
      stepId: stringValue(item.stepId) ?? "step",
      checkId: stringValue(item.checkId) ?? "check",
      status: stringValue(item.status) ?? "unknown",
      startedAt: nullableString(item.startedAt),
      finishedAt: nullableString(item.finishedAt),
      evidenceFile: evidencePath ? path.basename(evidencePath) : null,
      findingCount: arrayValue(item.findings).length,
      message: nullableString(item.message)
    };
  });

  return {
    ...summary,
    gate: {
      result: gateResultValue(gate.result) ?? summary.gateResult,
      blockingReasons: stringArrayValue(gate.blockingReasons)
    },
    findings,
    steps
  };
}

function progressFromDetail(detail: ScanRunDetailDto): PersistedScanRunProgress {
  const totalSteps = detail.steps.length;
  const completedSteps = detail.steps.filter((step) => ["passed", "failed", "skipped", "blocked", "error"].includes(step.status)).length;
  const failedSteps = detail.steps.filter((step) => step.status === "failed" || step.status === "error").length;
  const blockedSteps = detail.steps.filter((step) => step.status === "blocked").length;
  const finishedOrStartedAt = detail.finishedAt ?? detail.startedAt ?? new Date().toISOString();

  return {
    scanRunId: detail.id,
    status: detail.status,
    gateResult: detail.gateResult,
    totalSteps,
    completedSteps,
    failedSteps,
    blockedSteps,
    findingCount: detail.findingCount,
    startedAt: detail.startedAt,
    finishedAt: detail.finishedAt,
    updatedAt: detail.finishedAt ?? detail.startedAt,
    events: [
      {
        type: "scan.evidence.loaded",
        message: "Progress was derived from report evidence.",
        createdAt: finishedOrStartedAt
      }
    ]
  };
}

async function readScanRunReport(scanRunId: string, format: "markdown" | "json") {
  const fileName = format === "markdown" ? "report.md" : "report.json";
  const filePath = resolveScanRunFile(scanRunId, fileName);

  if (!filePath) {
    return null;
  }

  try {
    const content = await readFile(filePath, "utf8");

    return {
      scanRunId,
      format,
      fileName,
      contentType: format === "markdown" ? "text/markdown; charset=utf-8" : "application/json; charset=utf-8",
      content: format === "json" ? JSON.parse(content) : content
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }

    throw error;
  }
}

async function readScanRunSummary(scanRunId: string): Promise<ScanRunSummaryDto | null> {
  const scanRunDirectory = resolveScanRunDirectory(scanRunId);

  if (!scanRunDirectory) {
    return null;
  }

  try {
    const directoryStat = await stat(scanRunDirectory);

    if (!directoryStat.isDirectory()) {
      return null;
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }

    throw error;
  }

  const report = asRecord(await readScanRunJson(scanRunId, "report.json"));
  const execution = asRecord(await readScanRunJson(scanRunId, "execution-result.json"));
  const envelope = asRecord(await readScanRunJson(scanRunId, "central-result-envelope.json"));
  const scanRun = recordValue(report.scanRun) ?? recordValue(envelope.scanRun) ?? {};
  const project = recordValue(report.project) ?? recordValue(envelope.project) ?? {};
  const profile = recordValue(report.profile) ?? recordValue(envelope.profile) ?? {};
  const gate = recordValue(report.gate) ?? recordValue(execution.gate) ?? recordValue(envelope.gate) ?? {};
  const findings = arrayValue(report.findings ?? execution.findings ?? envelope.findings);
  const startedAt = nullableString(scanRun.startedAt) ?? nullableString(execution.startedAt);
  const finishedAt = nullableString(scanRun.finishedAt) ?? nullableString(execution.finishedAt);
  const files = await listScanRunFiles(scanRunId);

  if (!scanRun.id && !execution.scanRunId) {
    return null;
  }

  return {
    id: stringValue(scanRun.id) ?? stringValue(execution.scanRunId) ?? scanRunId,
    status: scanStatusValue(scanRun.status) ?? scanExecutionStatusValue(execution.status) ?? "unknown",
    gateResult: gateResultValue(scanRun.gateResult) ?? gateResultValue(gate.result) ?? "unknown",
    project: {
      id: stringValue(project.id) ?? "unknown",
      name: stringValue(project.name) ?? "Unknown project",
      dataClassification: stringValue(project.dataClassification) ?? "internal"
    },
    profile: {
      id: stringValue(profile.id) ?? stringValue(scanRun.profileId) ?? "unknown",
      name: stringValue(profile.name) ?? stringValue(scanRun.profileId) ?? "unknown"
    },
    startedAt,
    finishedAt,
    durationMs: durationMs(startedAt, finishedAt),
    findingCount: findings.length,
    severitySummary: severitySummaryValue(gate.summary ?? scanRun.summary),
    evidence: {
      root: scanRunDirectory,
      files,
      hasExecutionResult: files.includes("execution-result.json"),
      hasJsonReport: files.includes("report.json"),
      hasMarkdownReport: files.includes("report.md"),
      hasCentralEnvelope: files.includes("central-result-envelope.json"),
      hasSarifReport: files.includes("defectdojo.sarif.json"),
      hasCentralTelemetryDelivery: files.includes("central-telemetry-delivery.json"),
      hasDefectDojoDelivery: files.includes("defectdojo-delivery.json")
    }
  };
}

async function readScanRunJson(scanRunId: string, fileName: string): Promise<unknown> {
  const filePath = resolveScanRunFile(scanRunId, fileName);

  if (!filePath) {
    return null;
  }

  try {
    return JSON.parse(await readFile(filePath, "utf8"));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return null;
    }

    throw error;
  }
}

async function listScanRunFiles(scanRunId: string): Promise<string[]> {
  const scanRunDirectory = resolveScanRunDirectory(scanRunId);

  if (!scanRunDirectory) {
    return [];
  }

  try {
    const entries = await readdir(scanRunDirectory, { withFileTypes: true });
    return entries.filter((entry) => entry.isFile()).map((entry) => entry.name).sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }

    throw error;
  }
}

function resolveScanRunDirectory(scanRunId: string): string | null {
  const reportsPath = getReportsPath();
  const directoryPath = path.resolve(reportsPath, scanRunId);

  if (directoryPath !== reportsPath && directoryPath.startsWith(`${reportsPath}${path.sep}`)) {
    return directoryPath;
  }

  return null;
}

function resolveScanRunFile(scanRunId: string, fileName: string): string | null {
  const directoryPath = resolveScanRunDirectory(scanRunId);

  if (!directoryPath || path.basename(fileName) !== fileName) {
    return null;
  }

  return path.join(directoryPath, fileName);
}

function timestampValue(value: string | null): number {
  return value ? Date.parse(value) || 0 : 0;
}

function durationMs(startedAt: string | null, finishedAt: string | null): number | null {
  const start = timestampValue(startedAt);
  const end = timestampValue(finishedAt);

  return start > 0 && end > 0 && end >= start ? end - start : null;
}

function severitySummaryValue(value: unknown): SeveritySummary {
  const record = asRecord(value);

  return {
    critical: numberValue(record.critical) ?? 0,
    high: numberValue(record.high) ?? 0,
    medium: numberValue(record.medium) ?? 0,
    low: numberValue(record.low) ?? 0,
    info: numberValue(record.info) ?? 0
  };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function arrayValue(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function nullableString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function stringArrayValue(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function numberValue(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function scanStatusValue(value: unknown): ScanStatus | null {
  return value === "queued" || value === "running" || value === "completed" || value === "failed" || value === "cancelled" ? value : null;
}

function scanExecutionStatusValue(value: unknown): ScanStatus | null {
  return value === "completed" || value === "failed" ? value : null;
}

function gateResultValue(value: unknown): GateResult | null {
  return value === "pass" || value === "warning" || value === "fail" || value === "error" ? value : null;
}

function findingStatusValue(value: unknown): FindingStatus | null {
  return value === "open" || value === "accepted" || value === "false-positive" || value === "fixed" || value === "suppressed" ? value : null;
}

function isAllowedCorsOrigin(origin: string | undefined): boolean {
  if (!origin) return true;

  const configured = csv(process.env.SECURITY_PREFLIGHT_CORS_ORIGINS ?? process.env.CORS_ORIGINS);
  if (configured.includes("*")) return true;
  if (configured.includes(origin)) return true;

  if (process.env.APP_ENV !== "production" && /^http:\/\/(localhost|127\.0\.0\.1):\d+$/.test(origin)) {
    return true;
  }

  return false;
}

function csv(value: string | undefined): string[] {
  return (
    value
      ?.split(",")
      .map((item) => item.trim())
      .filter(Boolean) ?? []
  );
}

function buildPlanFromRequest(body: unknown, requestId: string):
  | { plan: ScanExecutionPlan }
  | {
      statusCode: number;
      error: {
        error: {
          code: string;
          message: string;
          details?: unknown[];
          requestId: string;
        };
      };
    } {
  const parsed = scanPlanRequestSchema.safeParse(body);

  if (!parsed.success) {
    return {
      statusCode: 400,
      error: {
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid scan plan request.",
          details: [parsed.error.flatten()],
          requestId
        }
      }
    };
  }

  const profile = defaultScanProfiles.find((candidate) => candidate.id === parsed.data.profileId);

  if (!profile) {
    return {
      statusCode: 404,
      error: {
        error: {
          code: "PROFILE_NOT_FOUND",
          message: `Scan profile '${parsed.data.profileId}' was not found.`,
          requestId
        }
      }
    };
  }

  return {
    plan: buildScanExecutionPlan({
      scanRunId: parsed.data.scanRunId,
      project: parsed.data.project,
      profile,
      dast: parsed.data.dast,
      reportsRoot: parsed.data.reportsRoot ?? process.env.REPORTS_PATH ?? "/reports"
    })
  };
}
