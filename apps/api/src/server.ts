import { randomUUID } from "node:crypto";
import cors from "@fastify/cors";
import Fastify, { type FastifyInstance } from "fastify";
import { defaultScanProfiles } from "@security-preflight/core";
import { runToolchainDoctor } from "@security-preflight/scanners";

export interface CreateServerOptions {
  logger?: boolean;
}

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

  server.get("/api/v1/toolchain/doctor", async () => runToolchainDoctor());

  return server;
}
