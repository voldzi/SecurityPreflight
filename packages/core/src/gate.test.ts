import { describe, expect, it } from "vitest";
import { createFindingFingerprint, defaultScanProfiles, evaluateGate, redactSecrets, type Finding } from "./index.js";

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

  it("does not count platform readiness gaps as application severity summary", () => {
    const profile = defaultScanProfiles.find((item) => item.name === "healthcare-reference")!;
    const result = evaluateGate(
      [
        {
          ...baseFinding,
          id: "finding-platform-1",
          type: "tooling",
          scope: "platform",
          severity: "high",
          title: "Greenbone/OpenVAS integration is not configured"
        }
      ],
      profile,
      "health-data"
    );

    expect(result.result).toBe("warning");
    expect(result.summary.high).toBe(0);
    expect(result.blockingReasons[0]).toContain("PLATFORM readiness gap");
  });
});

describe("createFindingFingerprint", () => {
  it("is stable for equivalent titles", () => {
    const first = createFindingFingerprint({ tool: "Semgrep", type: "sast", filePath: "src/app.ts", line: 10, title: " SQL Injection " });
    const second = createFindingFingerprint({ tool: "Semgrep", type: "sast", filePath: "src/app.ts", line: 10, title: "sql   injection" });

    expect(first).toBe(second);
  });
});

describe("redactSecrets", () => {
  it("preserves JSON escaping when redacting serialized nested evidence", () => {
    const payload = {
      evidence: JSON.stringify({
        RuleID: "generic-api-key",
        Fingerprint: "/srv/app:file:generic-api-key:secret-value"
      }),
      request: "Authorization: Bearer very-secret-token"
    };

    const redacted = redactSecrets(JSON.stringify(payload, null, 2));
    const parsed = JSON.parse(redacted) as typeof payload;

    expect(parsed.request).toBe("Authorization: Bearer ********");
    expect(parsed.evidence).toContain("generic-api-key:********");
    expect(() => JSON.parse(parsed.evidence)).not.toThrow();
  });
});
