#!/usr/bin/env node
import { spawn } from "node:child_process";
import { Command } from "commander";

const apiUrl = process.env.PREFLIGHT_API_URL ?? "http://localhost:8781";

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`);

  if (!response.ok) {
    throw new Error(`Request failed with HTTP ${response.status}`);
  }

  return (await response.json()) as T;
}

function runCompose(args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", ["compose", "-f", "infra/docker-compose.yml", ...args], {
      stdio: "inherit"
    });

    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`docker compose exited with ${code ?? "unknown"}`));
    });
  });
}

const program = new Command();

program.name("preflight").description("Local CLI for SecurityPreflight").version("0.1.0");

program.command("up").description("Start the local Docker Desktop stack").action(async () => {
  await runCompose(["up", "-d"]);
});

program.command("down").description("Stop the local Docker Desktop stack").action(async () => {
  await runCompose(["down"]);
});

program.command("status").description("Check API health").action(async () => {
  const health = await getJson<Record<string, unknown>>("/health");
  process.stdout.write(`${JSON.stringify(health, null, 2)}\n`);
});

program.command("doctor").description("Check local toolchain availability").action(async () => {
  const doctor = await getJson<Record<string, unknown>>("/api/v1/toolchain/doctor");
  process.stdout.write(`${JSON.stringify(doctor, null, 2)}\n`);
});

program
  .command("scan")
  .description("Queue a scan for a project path or id")
  .requiredOption("--project <project>", "Project path or id")
  .option("--profile <profile>", "Scan profile", "fast-local")
  .action((options: { project: string; profile: string }) => {
    process.stderr.write(`Scan queueing is scaffolded but not implemented yet: ${options.project} (${options.profile})\n`);
    process.exitCode = 3;
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 3;
});
