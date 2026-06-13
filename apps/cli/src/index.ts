#!/usr/bin/env node
import { spawn } from "node:child_process";
import path from "node:path";
import { Command } from "commander";

const apiUrl = process.env.PREFLIGHT_API_URL ?? "http://localhost:8781";
const invocationCwd = process.env.INIT_CWD ?? process.cwd();

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`);

  if (!response.ok) {
    throw new Error(`Request failed with HTTP ${response.status}`);
  }

  return (await response.json()) as T;
}

async function postJson<T>(urlPath: string, body: unknown): Promise<T> {
  const response = await fetch(`${apiUrl}${urlPath}`, {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const detail = await response.text();
    throw new Error(`Request failed with HTTP ${response.status}: ${detail}`);
  }

  return (await response.json()) as T;
}

function runCompose(args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", ["compose", "-f", "infra/docker-compose.yml", ...args], {
      cwd: invocationCwd,
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
  .option("--name <name>", "Project display name")
  .option("--dast-target <url>", "Explicit local or allowlisted DAST target URL")
  .option("--allow-active-dast", "Explicitly allow active DAST for profiles that support it", false)
  .option("--allow-host <host>", "Allowed DAST host; can be repeated", collect, [])
  .option("--dry-run", "Preview the execution plan without queueing scanner work", false)
  .action(
    async (options: {
      project: string;
      profile: string;
      name?: string;
      dastTarget?: string;
      allowActiveDast: boolean;
      allowHost: string[];
      dryRun: boolean;
    }) => {
      if (!options.dryRun) {
        process.stderr.write(
          `Scan queueing is scaffolded but not implemented yet: ${options.project} (${options.profile}). Use --dry-run to preview the execution plan.\n`
        );
        process.exitCode = 3;
        return;
      }

      const projectPath = path.resolve(invocationCwd, options.project);
      const plan = await postJson<{ blocked?: boolean }>("/api/v1/scans/plan", {
        profileId: options.profile,
        project: {
          id: projectPath,
          name: options.name ?? path.basename(projectPath),
          path: projectPath
        },
        dast:
          options.dastTarget || options.allowHost.length > 0 || options.allowActiveDast
            ? {
                targetUrl: options.dastTarget,
                allowedHosts: options.allowHost.length > 0 ? options.allowHost : undefined,
                allowActiveScan: options.allowActiveDast
              }
            : undefined
      });

      process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);

      if (plan.blocked) {
        process.exitCode = 2;
      }
    }
  );

function collect(value: string, previous: string[]): string[] {
  return [...previous, value];
}

program.parseAsync(process.argv).catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 3;
});
