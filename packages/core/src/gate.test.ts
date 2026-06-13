import { describe, expect, it } from "vitest";
import { createFindingFingerprint, defaultScanProfiles, evaluateGate, type Finding } from "./index.js";

const baseFinding: Finding = {
  id: "finding-1",
  scanRunId: "scan-1",
  tool: "Gitleaks",
  type: "secret",
  severity: "high",
  title: "Secret detected",
  description: "Credential-like value was found.",
  evidence: "redacted",
  filePath: ".env",
  line: 1,
  endpoint: null,
  cwe: null,
  cve: null,
  owasp: null,
  recommendation: "Remove and rotate the credential.",
  status: "open",
  fingerprint: "placeholder"
};

describe("evaluateGate", () => {
  it("fails when an open secret finding is present", () => {
    const profile = defaultScanProfiles.find((item) => item.name === "pre-release");

    expect(profile).toBeDefined();
    const result = evaluateGate([baseFinding], profile!, "internal");

    expect(result.result).toBe("fail");
    expect(result.blockingReasons[0]).toContain("secret");
  });

  it("passes when there are no findings", () => {
    const profile = defaultScanProfiles[0]!;

    expect(evaluateGate([], profile, "public").result).toBe("pass");
  });
});

describe("createFindingFingerprint", () => {
  it("is stable for equivalent titles", () => {
    const first = createFindingFingerprint({ tool: "Semgrep", type: "sast", filePath: "src/app.ts", line: 10, title: " SQL Injection " });
    const second = createFindingFingerprint({ tool: "Semgrep", type: "sast", filePath: "src/app.ts", line: 10, title: "sql   injection" });

    expect(first).toBe(second);
  });
});
