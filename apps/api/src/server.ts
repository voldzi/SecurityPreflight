import { createHash, randomUUID } from "node:crypto";
import path from "node:path";
import cors from "@fastify/cors";
import Fastify, { type FastifyInstance } from "fastify";
import { z } from "zod";
import { Queue } from "bullmq";
import { defaultScanProfiles, requiredScannerTools } from "@security-preflight/core";
import { buildScanExecutionPlan, type ScanExecutionPlan, runToolchainDoctor } from "@security-preflight/scanners";

export interface CreateServerOptions {
  logger?: boolean;
  scanQueue?: ScanQueue;
}

export interface ScanQueue {
  add(name: string, data: unknown, options?: Record<string, unknown>): Promise<{ id?: string | number }>;
}

const dataClassificationSchema = z.enum(["public", "internal", "confidential", "sensitive", "health-data"]);

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

  void server.register(cors, {
    origin: [/^http:\/\/localhost:\d+$/, /^http:\/\/127\.0\.0\.1:\d+$/]
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

  server.get("/api/v1/projects", async () => ({
    data: [],
    meta: {
      total: 0
    }
  }));

  server.get("/api/v1/scan-profiles", async () => ({
    data: defaultScanProfiles
  }));

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
