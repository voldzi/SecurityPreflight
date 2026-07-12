import { createServer } from "./server.js";

const port = Number.parseInt(process.env.APP_PORT ?? "8781", 10);
const host = process.env.APP_HOST ?? "0.0.0.0";
const server = createServer({ logger: true });

try {
  await server.listen({ host, port });
} catch (error) {
  server.log.error(error, "api failed to start");
  process.exit(1);
}
