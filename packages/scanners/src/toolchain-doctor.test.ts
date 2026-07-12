import { describe, expect, it } from "vitest";
import { runToolchainDoctor, type ToolCheckDefinition } from "./index.js";

describe("runToolchainDoctor", () => {
  it("separates healthcare-required and optional tool summaries", async () => {
    const checks: ToolCheckDefinition[] = [
      {
        id: "node",
        name: "Node.js",
        category: "runtime",
        requiredForHealthcare: true,
        command: "node",
        args: ["--version"]
      },
      {
        id: "zap",
        name: "OWASP ZAP",
        category: "dast",
        requiredForHealthcare: false,
        command: "security-preflight-missing-zap-test",
        args: ["--version"]
      }
    ];

    const result = await runToolchainDoctor(checks);

    expect(result.tools).toHaveLength(2);
    expect(result.tools[0]).toMatchObject({
      id: "node",
      category: "runtime",
      requiredForHealthcare: true,
      status: "available"
    });
    expect(result.tools[1]).toMatchObject({
      id: "zap",
      category: "dast",
      requiredForHealthcare: false,
      status: "missing"
    });
    expect(result.summary).toMatchObject({
      available: 1,
      missing: 1,
      error: 0,
      healthcareAvailable: 1,
      healthcareMissing: 0,
      healthcareError: 0,
      optionalAvailable: 0,
      optionalMissing: 1,
      optionalError: 0
    });
  });
});
