"use client";

import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ClipboardList,
  FileWarning,
  FolderGit2,
  LayoutDashboard,
  Play,
  ScrollText,
  Settings,
  ShieldCheck,
  TerminalSquare,
  Wrench
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

const navItems = [
  { label: "Dashboard", icon: LayoutDashboard, active: true },
  { label: "Projects", icon: FolderGit2 },
  { label: "Scans", icon: Activity },
  { label: "Findings", icon: FileWarning },
  { label: "Reports", icon: ScrollText },
  { label: "Toolchain", icon: Wrench },
  { label: "Settings", icon: Settings }
];

const projects = [
  { name: "SecurityPreflight", path: "/workspace/projects", stack: "Next.js / Fastify", data: "internal", gate: "READY", high: 0, medium: 0 },
  { name: "Hospital API", path: "~/Projects/hospital-api", stack: "Node.js / OpenAPI", data: "health-data", gate: "FAIL", high: 2, medium: 5 },
  { name: "Claims Portal", path: "~/Projects/claims-portal", stack: "Next.js / Docker", data: "sensitive", gate: "WARNING", high: 0, medium: 3 }
];

const scans = [
  { project: "SecurityPreflight", profile: "documentation-compliance", started: "local", duration: "queue", result: "READY" },
  { project: "Hospital API", profile: "healthcare-reference", started: "planned", duration: "strict", result: "FAIL" },
  { project: "Claims Portal", profile: "fast-local", started: "planned", duration: "quick", result: "WARNING" }
];

const fallbackTools = [
  { name: "Docker Desktop", status: "available", version: "compose runtime" },
  { name: "Gitleaks", status: "container", version: "worker/toolbox" },
  { name: "Semgrep", status: "container", version: "worker/toolbox" },
  { name: "Trivy", status: "container", version: "worker/toolbox" },
  { name: "Syft / Grype / OSV", status: "container", version: "worker/toolbox" },
  { name: "Checkov IaC", status: "container", version: "worker/toolbox" },
  { name: "Central results API", status: "available", version: "v1 envelope" }
];

const findings = [
  { title: "Healthcare profile blocks medium-or-higher findings", meta: "policy / gate", severity: "HIGH" },
  { title: "External scanner failures are fail-closed", meta: "worker / evidence", severity: "HIGH" },
  { title: "Central telemetry envelope redacts evidence", meta: "results ingest / OpenAPI", severity: "MEDIUM" }
];

interface ScanProfile {
  id: string;
  name: string;
  description: string;
  checks: string[];
}

interface ToolchainDoctor {
  checkedAt: string;
  tools: Array<{
    name: string;
    status: string;
    version: string | null;
    message: string | null;
  }>;
  summary: {
    available: number;
    missing: number;
    error: number;
  };
}

interface ScanActionResult {
  mode: "plan" | "queue";
  status: "idle" | "loading" | "success" | "error";
  message: string;
  scanRunId?: string;
  blocked?: boolean;
  gate?: string;
  stepCount?: number;
}

const apiBaseUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8781";
const dockerProjectPath = "/workspace/projects";

function toneFor(value: string) {
  if (["PASS", "READY", "ready", "available", "container", "success", "queued"].includes(value)) return "ok";
  if (["WARNING", "MEDIUM", "idle", "loading"].includes(value)) return "warn";
  if (["FAIL", "HIGH", "missing", "error", "blocked"].includes(value)) return "fail";
  return undefined;
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...init?.headers
    }
  });
  const payload = (await response.json()) as T & { error?: { message?: string } };

  if (!response.ok) {
    throw new Error(payload.error?.message ?? `Request failed with status ${response.status}`);
  }

  return payload;
}

export default function DashboardPage() {
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("documentation-compliance");
  const [doctor, setDoctor] = useState<ToolchainDoctor | null>(null);
  const [loadingDoctor, setLoadingDoctor] = useState(false);
  const [scanResult, setScanResult] = useState<ScanActionResult>({
    mode: "plan",
    status: "idle",
    message: "Ready to run a local scan through the Docker worker."
  });

  const selectedProfile = useMemo(
    () => profiles.find((profile) => profile.id === selectedProfileId),
    [profiles, selectedProfileId]
  );
  const renderedTools = doctor?.tools.length
    ? doctor.tools.map((tool) => ({
        name: tool.name,
        status: tool.status,
        version: tool.version ?? tool.message ?? "not reported"
      }))
    : fallbackTools;
  const gateTone = scanResult.status === "error" || scanResult.blocked ? "fail" : scanResult.status === "success" ? "ok" : "warn";

  useEffect(() => {
    let active = true;

    async function loadProfiles() {
      try {
        const payload = await fetchJson<{ data: ScanProfile[] }>(`${apiBaseUrl}/api/v1/scan-profiles`);

        if (!active) return;

        setProfiles(payload.data);
        if (!payload.data.some((profile) => profile.id === selectedProfileId)) {
          setSelectedProfileId(payload.data[0]?.id ?? "documentation-compliance");
        }
      } catch (error) {
        if (!active) return;

        setScanResult({
          mode: "plan",
          status: "error",
          message: error instanceof Error ? error.message : "Failed to load scan profiles."
        });
      }
    }

    void loadProfiles();

    return () => {
      active = false;
    };
  }, [selectedProfileId]);

  async function refreshDoctor() {
    setLoadingDoctor(true);

    try {
      const payload = await fetchJson<ToolchainDoctor>(`${apiBaseUrl}/api/v1/toolchain/doctor`);
      setDoctor(payload);
    } catch (error) {
      setScanResult({
        mode: "plan",
        status: "error",
        message: error instanceof Error ? error.message : "Toolchain doctor failed."
      });
    } finally {
      setLoadingDoctor(false);
    }
  }

  async function runScan(mode: "plan" | "queue") {
    const scanRunId = `scan_ui_${Date.now().toString(36)}`;
    setScanResult({
      mode,
      status: "loading",
      message: mode === "plan" ? "Building scan plan..." : "Queueing scan job...",
      scanRunId
    });

    try {
      const requestBody = {
        scanRunId,
        profileId: selectedProfileId,
        reportsRoot: "/reports",
        project: {
          id: "security-preflight-local",
          name: "SecurityPreflight",
          path: dockerProjectPath,
          dataClassification: selectedProfileId === "healthcare-reference" ? "health-data" : "internal"
        }
      };
      const endpoint = mode === "plan" ? "plan" : "queue";
      const payload = await fetchJson<any>(`${apiBaseUrl}/api/v1/scans/${endpoint}`, {
        method: "POST",
        body: JSON.stringify(requestBody)
      });
      const plan = mode === "queue" ? payload.data.plan : payload;

      setScanResult({
        mode,
        status: "success",
        message:
          mode === "plan"
            ? plan.blocked
              ? "Scan plan was created, but guardrails block execution."
              : "Scan plan is ready and can be queued."
            : "Scan job was queued. Worker will write evidence under /reports.",
        scanRunId,
        blocked: plan.blocked,
        gate: mode === "queue" ? "queued" : plan.blocked ? "blocked" : "ready",
        stepCount: plan.steps?.length ?? 0
      });
    } catch (error) {
      setScanResult({
        mode,
        status: "error",
        message: error instanceof Error ? error.message : "Scan action failed.",
        scanRunId
      });
    }
  }

  return (
    <main className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={18} strokeWidth={2} />
          </div>
          <span>SecurityPreflight</span>
        </div>

        <nav className="nav-group">
          {navItems.map((item) => (
            <button key={item.label} className="nav-item" data-active={item.active} type="button">
              <item.icon size={17} strokeWidth={2} />
              <span>{item.label}</span>
            </button>
          ))}
        </nav>
      </aside>

      <section className="main">
        <header className="topbar">
          <div className="title-block">
            <p className="kicker">STRATOS Security Workspace</p>
            <h1>SecurityPreflight</h1>
            <p>Local evidence gate for sensitive applications, scanner readiness, and central result export.</p>
          </div>
          <div className="status-row" aria-label="Runtime status">
            <span className="chip" data-tone="ok">Local only</span>
            <span className="chip" data-tone="ok">Docker Desktop</span>
            <span className="chip" data-tone="warn">DAST disabled</span>
          </div>
        </header>

        <div className="content-grid">
          <div className="stack">
            <section className="panel surface-lift" aria-labelledby="readiness-heading">
              <div className="panel-header">
                <h2 id="readiness-heading">Scan Readiness</h2>
                <span>{doctor ? `Checked ${new Date(doctor.checkedAt).toLocaleTimeString()}` : "Live API connected"}</span>
              </div>
              <div className="summary-grid">
                <div className="summary-item">
                  <p className="summary-label">Profiles</p>
                  <p className="summary-value">{profiles.length || "-"} <small>available</small></p>
                </div>
                <div className="summary-item">
                  <p className="summary-label">Toolchain</p>
                  <p className="summary-value" style={{ color: doctor?.summary.error || doctor?.summary.missing ? "var(--fail)" : "var(--ok)" }}>
                    {doctor ? doctor.summary.available : "-"} <small>available</small>
                  </p>
                </div>
                <div className="summary-item">
                  <p className="summary-label">Last action</p>
                  <p className="summary-value">{scanResult.gate ?? scanResult.status} <small>{scanResult.mode}</small></p>
                </div>
                <div className="summary-item">
                  <p className="summary-label">Reports</p>
                  <p className="summary-value">/reports <small>volume</small></p>
                </div>
              </div>
            </section>

            <section className="panel" aria-labelledby="projects-heading">
              <div className="panel-header">
                <h2 id="projects-heading">Projects</h2>
                <button className="button" type="button">
                  <FolderGit2 size={15} />
                  Add project
                </button>
              </div>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Project</th>
                      <th>Stack</th>
                      <th>Data</th>
                      <th>Gate</th>
                      <th>Open</th>
                    </tr>
                  </thead>
                  <tbody>
                    {projects.map((project) => (
                      <tr key={project.name}>
                        <td>
                          <strong>{project.name}</strong>
                          <div className="mono muted">{project.path}</div>
                        </td>
                        <td>{project.stack}</td>
                        <td><span className="chip">{project.data}</span></td>
                        <td><span className="chip" data-tone={toneFor(project.gate)}>{project.gate}</span></td>
                        <td>{project.high} high / {project.medium} medium</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>

            <div className="split">
              <section className="panel" aria-labelledby="scans-heading">
                <div className="panel-header">
                  <h2 id="scans-heading">Recent Scans</h2>
                  <span>Local history</span>
                </div>
                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Project</th>
                        <th>Profile</th>
                        <th>Mode</th>
                        <th>Result</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scans.map((scan) => (
                        <tr key={`${scan.project}-${scan.started}`}>
                          <td>{scan.project}</td>
                          <td className="mono">{scan.profile}</td>
                          <td>{scan.duration}</td>
                          <td><span className="chip" data-tone={toneFor(scan.result)}>{scan.result}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="panel" aria-labelledby="toolchain-heading">
                <div className="panel-header">
                  <h2 id="toolchain-heading">Toolchain Doctor</h2>
                  <button className="button compact" disabled={loadingDoctor} onClick={refreshDoctor} type="button">
                    <Wrench size={14} />
                    {loadingDoctor ? "Checking" : "Check"}
                  </button>
                </div>
                <div className="tool-list">
                  {renderedTools.map((tool) => (
                    <div className="tool-row" key={tool.name}>
                      <div>
                        <strong>{tool.name}</strong>
                        <div className="mono muted">{tool.version}</div>
                      </div>
                      <span className="chip" data-tone={toneFor(tool.status)}>{tool.status}</span>
                    </div>
                  ))}
                </div>
              </section>
            </div>

            <section className="panel" aria-labelledby="findings-heading">
              <div className="panel-header">
                <h2 id="findings-heading">Blocking Controls</h2>
                <span>Healthcare reference policy</span>
              </div>
              <div className="finding-list">
                {findings.map((finding) => (
                  <div className="finding-row" key={finding.title}>
                    <div>
                      <p className="finding-title">{finding.title}</p>
                      <p className="finding-meta">{finding.meta}</p>
                    </div>
                    <span className="chip" data-tone={toneFor(finding.severity)}>{finding.severity}</span>
                  </div>
                ))}
              </div>
            </section>
          </div>

          <aside className="panel detail-panel surface-lift" aria-labelledby="selected-scan-heading">
            <div className="panel-header">
              <h2 id="selected-scan-heading">Run Scan</h2>
              <span className="chip" data-tone={gateTone}>{scanResult.gate ?? scanResult.status}</span>
            </div>
            <div className="gate-block">
              <div className="gate-result">
                <div>
                  <div className="muted">Selected profile</div>
                  <strong className="profile-name">{selectedProfile?.name ?? selectedProfileId}</strong>
                </div>
                <div className="icon-box">
                  {scanResult.status === "error" || scanResult.blocked ? <AlertTriangle size={18} /> : <CheckCircle2 size={18} />}
                </div>
              </div>
              <label className="field-label" htmlFor="scan-profile">Profile</label>
              <select
                className="select"
                id="scan-profile"
                onChange={(event) => setSelectedProfileId(event.target.value)}
                value={selectedProfileId}
              >
                {profiles.map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.name}
                  </option>
                ))}
              </select>
              <p className="muted profile-description">{selectedProfile?.description}</p>
            </div>
            <div className="detail-list">
              <div className="detail-row">
                <span>Project path</span>
                <strong className="mono">{dockerProjectPath}</strong>
              </div>
              <div className="detail-row">
                <span>Project</span>
                <strong>SecurityPreflight</strong>
              </div>
              <div className="detail-row">
                <span>Checks</span>
                <strong>{selectedProfile?.checks.length ?? 0}</strong>
              </div>
              <div className="detail-row">
                <span>Tools</span>
                <strong>{doctor ? `${doctor.summary.available} available` : "not checked"}</strong>
              </div>
            </div>
            <div className="button-row">
              <button
                className="button"
                data-primary="true"
                disabled={scanResult.status === "loading"}
                onClick={() => runScan("queue")}
                type="button"
              >
                <Play size={14} />
                Run scan
              </button>
              <button
                className="button"
                disabled={scanResult.status === "loading"}
                onClick={() => runScan("plan")}
                type="button"
              >
                <ClipboardList size={14} />
                Dry run
              </button>
              <button className="button" disabled type="button" aria-label="Open scan log">
                <TerminalSquare size={14} />
              </button>
            </div>
            <div className="detail-body">
              <div className="result-box" data-tone={gateTone} role="status">
                <strong>{scanResult.status === "loading" ? "Working" : scanResult.status}</strong>
                <p>{scanResult.message}</p>
                {scanResult.scanRunId ? <code>{scanResult.scanRunId}</code> : null}
                {scanResult.stepCount != null ? <span>{scanResult.stepCount} planned steps</span> : null}
              </div>
              <p className="muted">
                Worker reports are written to the Docker reports volume under the scan run id.
              </p>
            </div>
          </aside>
        </div>
      </section>
    </main>
  );
}
