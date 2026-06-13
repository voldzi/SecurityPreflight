import { readFile } from "node:fs/promises";
import { Worker } from "bullmq";
import type { ScanExecutionPlan } from "@security-preflight/scanners";
import { executeScanJob } from "./scan-job.js";

const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379/0";
const queueName = process.env.SCAN_QUEUE_NAME ?? "security-preflight-scans";
const workerConcurrency = Number.parseInt(process.env.WORKER_CONCURRENCY ?? "1", 10);

const log = (message: string, extra: Record<string, unknown> = {}) => {
  process.stdout.write(
    `${JSON.stringify({
      timestamp: new Date().toISOString(),
      level: "info",
      service: "security-preflight-worker",
      message,
      requestId: extra.requestId ?? "worker_boot",
      environment: process.env.APP_ENV ?? "development",
      version: process.env.npm_package_version ?? "0.1.0",
      ...extra
    })}\n`
  );
};

log("worker initialized", {
  queueName,
  workerConcurrency,
  scannerNetworkMode: process.env.SCANNER_NETWORK_MODE ?? "none",
  allowDockerSocket: process.env.ALLOW_DOCKER_SOCKET === "true",
  allowActiveDast: process.env.ALLOW_ACTIVE_DAST === "true"
});

if (process.env.RUN_ONCE === "1") {
  if (process.env.SCAN_PLAN_FILE) {
    const plan = JSON.parse(await readFile(process.env.SCAN_PLAN_FILE, "utf8")) as ScanExecutionPlan;
    const result = await executeScanJob({
      plan,
      requestId: process.env.REQUEST_ID ?? "worker_run_once"
    });
    log("worker run-once scan complete", {
      scanRunId: result.scanRunId,
      gateResult: result.gateResult,
      findingCount: result.findingCount,
      reportPaths: result.reportPaths
    });
  } else {
    log("worker run-once complete");
  }

  process.exit(0);
}

const worker = new Worker(
  queueName,
  async (job) => {
    if (job.name !== "scan.execute") {
      throw new Error(`Unsupported job name: ${job.name}`);
    }

    return executeScanJob({
      plan: (job.data as { plan: ScanExecutionPlan }).plan,
      requestId: (job.data as { requestId?: string }).requestId
    });
  },
  {
    connection: {
      url: redisUrl
    },
    concurrency: Number.isFinite(workerConcurrency) && workerConcurrency > 0 ? workerConcurrency : 1
  }
);

worker.on("completed", (job, result: unknown) => {
  log("scan job completed", {
    jobId: job.id,
    scanRunId: (result as { scanRunId?: string }).scanRunId,
    gateResult: (result as { gateResult?: string }).gateResult,
    findingCount: (result as { findingCount?: number }).findingCount
  });
});

worker.on("failed", (job, error) => {
  log("scan job failed", {
    level: "error",
    jobId: job?.id,
    error: error.message
  });
});

const shutdown = async () => {
  await worker.close();
  log("worker stopped");
  process.exit(0);
};

process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());
