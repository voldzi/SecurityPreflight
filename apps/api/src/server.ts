import { randomUUID } from "node:crypto";
import path from "node:path";
import cors from "@fastify/cors";
import Fastify, { type FastifyInstance } from "fastify";
import { z } from "zod";
import { defaultScanProfiles } from "@security-preflight/core";
import { buildScanExecutionPlan, runToolchainDoctor } from "@security-preflight/scanners";

export interface CreateServerOptions {
  logger?: boolean;
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

export function createServer(options: CreateServerOptions = {}): FastifyInstance {
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

  server.post("/api/v1/scans/plan", async (request, reply) => {
    const parsed = scanPlanRequestSchema.safeParse(request.body);

    if (!parsed.success) {
      return reply.status(400).send({
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid scan plan request.",
          details: parsed.error.flatten(),
          requestId: request.id
        }
      });
    }

    const profile = defaultScanProfiles.find((candidate) => candidate.id === parsed.data.profileId);

    if (!profile) {
      return reply.status(404).send({
        error: {
          code: "PROFILE_NOT_FOUND",
          message: `Scan profile '${parsed.data.profileId}' was not found.`,
          requestId: request.id
        }
      });
    }

    return buildScanExecutionPlan({
      scanRunId: parsed.data.scanRunId,
      project: parsed.data.project,
      profile,
      dast: parsed.data.dast,
      reportsRoot: parsed.data.reportsRoot ?? process.env.REPORTS_PATH ?? "/reports"
    });
  });

  server.get("/api/v1/toolchain/doctor", async () => runToolchainDoctor());

  return server;
}
