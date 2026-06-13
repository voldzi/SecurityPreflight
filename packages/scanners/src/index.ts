import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export type ToolStatus = "available" | "missing" | "error";

export interface ToolCheckResult {
  name: string;
  command: string;
  status: ToolStatus;
  version: string | null;
  message: string | null;
}

export interface ToolchainDoctorResult {
  checkedAt: string;
  tools: ToolCheckResult[];
  summary: {
    available: number;
    missing: number;
    error: number;
  };
}

export const defaultToolChecks: Array<{ name: string; command: string; args: string[] }> = [
  { name: "Docker", command: "docker", args: ["--version"] },
  { name: "Docker Compose", command: "docker", args: ["compose", "version"] },
  { name: "Gitleaks", command: "gitleaks", args: ["version"] },
  { name: "Semgrep", command: "semgrep", args: ["--version"] },
  { name: "Trivy", command: "trivy", args: ["--version"] },
  { name: "Redocly", command: "npx", args: ["--yes", "@redocly/cli@latest", "--version"] }
];

export async function runToolchainDoctor(
  checks: Array<{ name: string; command: string; args: string[] }> = defaultToolChecks
): Promise<ToolchainDoctorResult> {
  const tools = await Promise.all(
    checks.map(async (check) => {
      try {
        const { stdout, stderr } = await execFileAsync(check.command, check.args, { timeout: 15_000 });
        const version = (stdout || stderr).trim().split("\n")[0] ?? null;

        return {
          name: check.name,
          command: [check.command, ...check.args].join(" "),
          status: "available" as const,
          version,
          message: null
        };
      } catch (error) {
        const nodeError = error as NodeJS.ErrnoException;
        const isMissing = nodeError.code === "ENOENT";

        return {
          name: check.name,
          command: [check.command, ...check.args].join(" "),
          status: isMissing ? ("missing" as const) : ("error" as const),
          version: null,
          message: nodeError.message
        };
      }
    })
  );

  return {
    checkedAt: new Date().toISOString(),
    tools,
    summary: {
      available: tools.filter((tool) => tool.status === "available").length,
      missing: tools.filter((tool) => tool.status === "missing").length,
      error: tools.filter((tool) => tool.status === "error").length
    }
  };
}
