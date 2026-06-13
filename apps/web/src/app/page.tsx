import {
  Activity,
  ClipboardList,
  Download,
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
  { name: "Hospital API", path: "~/Projects/hospital-api", stack: "Node.js / OpenAPI", data: "health-data", gate: "FAIL", high: 2, medium: 5 },
  { name: "Claims Portal", path: "~/Projects/claims-portal", stack: "Next.js / Docker", data: "sensitive", gate: "WARNING", high: 0, medium: 3 },
  { name: "Ops Runbooks", path: "~/Projects/ops-runbooks", stack: "Docs", data: "internal", gate: "PASS", high: 0, medium: 0 }
];

const scans = [
  { project: "Hospital API", profile: "pre-release", started: "16:12", duration: "08m 42s", result: "FAIL" },
  { project: "Claims Portal", profile: "fast-local", started: "15:48", duration: "01m 37s", result: "WARNING" },
  { project: "Ops Runbooks", profile: "documentation-compliance", started: "14:30", duration: "00m 22s", result: "PASS" }
];

const tools = [
  { name: "Docker Desktop", status: "available", version: "29.5.3" },
  { name: "Gitleaks", status: "container", version: "scanner-toolbox" },
  { name: "Semgrep", status: "container", version: "scanner-toolbox" },
  { name: "Trivy", status: "container", version: "scanner-toolbox" },
  { name: "OpenAPI", status: "available", version: "Redocly" },
  { name: "Syft SBOM", status: "container", version: "scanner-toolbox" },
  { name: "Grype / OSV", status: "container", version: "scanner-toolbox" },
  { name: "Checkov IaC", status: "container", version: "scanner-toolbox" },
  { name: "Central results API", status: "available", version: "v1 envelope" }
];

const findings = [
  { title: "Secret detected in environment file", meta: ".env:1 / Gitleaks", severity: "HIGH" },
  { title: "Missing ErrorResponse schema on 4xx response", meta: "openapi/openapi.json / OpenAPI", severity: "HIGH" },
  { title: "Audit logging retention not documented", meta: "docs/security.md / Documentation", severity: "MEDIUM" }
];

function toneFor(value: string) {
  if (["PASS", "available", "container"].includes(value)) return "ok";
  if (["WARNING", "MEDIUM"].includes(value)) return "warn";
  if (["FAIL", "HIGH", "missing"].includes(value)) return "fail";
  return undefined;
}

export default function DashboardPage() {
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
            <h1>SecurityPreflight</h1>
          </div>
          <div className="status-row" aria-label="Runtime status">
            <span className="chip" data-tone="ok">Local only</span>
            <span className="chip" data-tone="ok">Docker Desktop</span>
            <span className="chip" data-tone="warn">DAST disabled</span>
          </div>
        </header>

        <div className="content-grid">
          <div className="stack">
            <section className="panel" aria-labelledby="readiness-heading">
              <div className="panel-header">
                <h2 id="readiness-heading">Scan Readiness</h2>
                <span>Last refreshed 16:34</span>
              </div>
              <div className="summary-grid">
                <div className="summary-item">
                  <p className="summary-label">Projects</p>
                  <p className="summary-value">3 <small>registered</small></p>
                </div>
                <div className="summary-item">
                  <p className="summary-label">Gate failures</p>
                  <p className="summary-value" style={{ color: "var(--fail)" }}>1 <small>blocking</small></p>
                </div>
                <div className="summary-item">
                  <p className="summary-label">Critical / High</p>
                  <p className="summary-value">2 <small>open</small></p>
                </div>
                <div className="summary-item">
                  <p className="summary-label">Reports</p>
                  <p className="summary-value">7 <small>local</small></p>
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
                        <th>Time</th>
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
                  <span>Scanner mode: toolbox</span>
                </div>
                <div className="tool-list">
                  {tools.map((tool) => (
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
                <h2 id="findings-heading">Top Blocking Findings</h2>
                <span>Sorted by gate impact</span>
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

          <aside className="panel detail-panel" aria-labelledby="selected-scan-heading">
            <div className="panel-header">
              <h2 id="selected-scan-heading">Selected Scan</h2>
              <span className="chip" data-tone="fail">FAIL</span>
            </div>
            <div className="gate-block">
              <div className="gate-result">
                <div>
                  <div className="muted">Release gate</div>
                  <strong style={{ color: "var(--fail)" }}>FAIL</strong>
                </div>
                <div className="icon-box">
                  <FileWarning size={18} />
                </div>
              </div>
              <div className="progress-track" aria-hidden="true">
                <div className="progress-bar" />
              </div>
            </div>
            <div className="detail-list">
              <div className="detail-row">
                <span>Profile</span>
                <strong className="mono">pre-release</strong>
              </div>
              <div className="detail-row">
                <span>Project</span>
                <strong>Hospital API</strong>
              </div>
              <div className="detail-row">
                <span>Branch</span>
                <strong className="mono">main</strong>
              </div>
              <div className="detail-row">
                <span>Tools</span>
                <strong>4 passed</strong>
              </div>
            </div>
            <div className="button-row">
              <button className="button" data-primary="true" type="button">
                <Play size={14} />
                Run scan
              </button>
              <button className="button" type="button">
                <Download size={14} />
                Report
              </button>
              <button className="button" type="button" aria-label="Open scan log">
                <TerminalSquare size={14} />
              </button>
            </div>
            <div className="detail-body">
              <p className="muted">
                Markdown and JSON reports are stored locally under the configured report volume.
              </p>
              <div className="chip" data-tone="ok">
                <ClipboardList size={14} />
                Audit trail ready
              </div>
            </div>
          </aside>
        </div>
      </section>
    </main>
  );
}
