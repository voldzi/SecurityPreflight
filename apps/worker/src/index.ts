import { Queue } from "bullmq";

const redisUrl = process.env.REDIS_URL ?? "redis://localhost:6379/0";
const queueName = process.env.SCAN_QUEUE_NAME ?? "security-preflight-scans";

const queue = new Queue(queueName, {
  connection: {
    url: redisUrl
  }
});

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
  scannerNetworkMode: process.env.SCANNER_NETWORK_MODE ?? "none",
  allowDockerSocket: process.env.ALLOW_DOCKER_SOCKET === "true",
  allowActiveDast: process.env.ALLOW_ACTIVE_DAST === "true"
});

if (process.env.RUN_ONCE === "1") {
  await queue.close();
  log("worker run-once complete");
  process.exit(0);
}

const shutdown = async () => {
  await queue.close();
  log("worker stopped");
  process.exit(0);
};

process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());
