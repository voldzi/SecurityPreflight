"use client";

import {
  Activity,
  AlertTriangle,
  Archive,
  CheckCircle2,
  ClipboardList,
  Database,
  FileJson,
  FileWarning,
  FolderGit2,
  Gauge,
  History,
  LayoutDashboard,
  Play,
  ScrollText,
  Settings,
  ShieldCheck,
  TerminalSquare,
  Wrench
} from "lucide-react";
import {
  AppRail,
  AppShell,
  Badge,
  Button,
  DataGridShell,
  DataTable,
  DetailSurface,
  IconButton,
  MetricCard,
  ProgressBar,
  RagBadge,
  SearchBox,
  SelectField,
  StructuredList,
  Topbar,
  ViewTabs,
  ViewToolbar,
  WorkspaceNav,
  WorkspaceSidebar,
  type BadgeTone,
  type DataTableColumn,
  type DetailSurfaceMode,
  type RagStatus,
  type WorkspaceNavGroup
} from "@voldzi/stratos-ui";
import { useEffect, useMemo, useState } from "react";

type WorkspaceView = "dashboard" | "capabilities" | "execution" | "telemetry";
type CapabilityStatus = "Ready" | "Partial" | "Gap" | "Blocked";

interface ScanProfile {
  id: string;
  name: string;
  description: string;
  checks: string[];
}

interface ToolchainDoctor {
  checkedAt: string;
  tools: Array<{
    id: string;
    name: string;
    category: string;
    requiredForHealthcare: boolean;
    status: string;
    version: string | null;
    message: string | null;
  }>;
  summary: {
    available: number;
    missing: number;
    error: number;
    healthcareAvailable: number;
    healthcareMissing: number;
    healthcareError: number;
    optionalAvailable: number;
    optionalMissing: number;
    optionalError: number;
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

interface ScanRunSummary {
  id: string;
  status: string;
  gateResult: string;
  project: {
    id: string;
    name: string;
    dataClassification: string;
  };
  profile: {
    id: string;
    name: string;
  };
  startedAt: string | null;
  finishedAt: string | null;
  durationMs: number | null;
  findingCount: number;
  severitySummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  evidence: {
    root: string;
    files: string[];
    hasExecutionResult: boolean;
    hasJsonReport: boolean;
    hasMarkdownReport: boolean;
    hasCentralEnvelope: boolean;
  };
}

interface ScanRunDetail extends ScanRunSummary {
  gate: {
    result: string;
    blockingReasons: string[];
  };
  findings: Array<{
    id: string;
    tool: string;
    type: string;
    severity: string;
    title: string;
    filePath: string | null;
    line: number | null;
    endpoint: string | null;
    status: string;
    recommendation: string;
  }>;
  steps: Array<{
    stepId: string;
    checkId: string;
    status: string;
    startedAt: string | null;
    finishedAt: string | null;
    evidenceFile: string | null;
    findingCount: number;
    message: string | null;
  }>;
}

interface ProjectRow {
  id: string;
  name: string;
  path: string;
  stack: string;
  data: string;
  gate: string;
  findings: string;
}

interface ScanRow {
  id: string;
  project: string;
  profile: string;
  status: string;
  result: string;
  findings: string;
  finished: string;
}

interface CapabilityRow {
  id: string;
  area: string;
  status: CapabilityStatus;
  implemented: string;
  gap: string;
  priority: string;
}

const apiBaseUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8781";
const dockerProjectPath = "/workspace/projects";

const projectRows: ProjectRow[] = [
  {
    id: "security-preflight",
    name: "SecurityPreflight",
    path: "/workspace/projects",
    stack: "Next.js / Fastify / Worker",
    data: "internal",
    gate: "READY",
    findings: "0 high / 0 medium"
  },
  {
    id: "hospital-api",
    name: "Hospital API",
    path: "~/Projects/hospital-api",
    stack: "Node.js / OpenAPI",
    data: "health-data",
    gate: "FAIL",
    findings: "2 high / 5 medium"
  },
  {
    id: "claims-portal",
    name: "Claims Portal",
    path: "~/Projects/claims-portal",
    stack: "Next.js / Docker",
    data: "sensitive",
    gate: "WARNING",
    findings: "0 high / 3 medium"
  }
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

const capabilityRows: CapabilityRow[] = [
  {
    id: "scan-planning",
    area: "Scan planning and guardrails",
    status: "Ready",
    implemented: "Profiles, dry-run planning, blocked active DAST, command evidence paths.",
    gap: "Add per-project policy overrides and diff-aware profile selection.",
    priority: "P1"
  },
  {
    id: "worker-execution",
    area: "Worker execution",
    status: "Partial",
    implemented: "Queue endpoint, worker consumer, internal checks, external scanner runner.",
    gap: "No live progress stream, cancellation, or retry queue yet.",
    priority: "P0"
  },
  {
    id: "healthcare-reference",
    area: "Healthcare reference checks",
    status: "Partial",
    implemented: "Strict profile, fail-closed scanner evidence, central envelope redaction.",
    gap: "Needs policy catalog, retention matrix, access-control assertions, and audit-log review checks.",
    priority: "P0"
  },
  {
    id: "findings",
    area: "Finding management",
    status: "Gap",
    implemented: "Normalized finding model and report output exist in packages.",
    gap: "No UI for triage, exceptions, owners, remediation SLA, or evidence drill-down.",
    priority: "P0"
  },
  {
    id: "reports",
    area: "Reports and evidence",
    status: "Partial",
    implemented: "Markdown, JSON, execution-result, central-result envelope files, and live evidence browser.",
    gap: "No download workflow, SARIF/SBOM export view, or evidence retention controls.",
    priority: "P1"
  },
  {
    id: "telemetry",
    area: "Central telemetry",
    status: "Partial",
    implemented: "OpenAPI ingest endpoint and redacted result envelope contract.",
    gap: "No configured remote sink, signing, retry buffer, or delivery status timeline.",
    priority: "P1"
  },
  {
    id: "projects",
    area: "Project registry",
    status: "Gap",
    implemented: "Dashboard shows representative projects and fixed Docker mount path.",
    gap: "Needs persistent project CRUD, path validation, stack detector results, and per-project settings.",
    priority: "P0"
  },
  {
    id: "auth",
    area: "Authentication and authorization",
    status: "Blocked",
    implemented: "Local-only single-user boundary is documented.",
    gap: "Any shared or central deployment needs AuthN/AuthZ, TLS, RBAC, and audit identities first.",
    priority: "P0"
  }
];

const executionStages = [
  {
    id: "intake",
    title: "Project intake",
    meta: "fixed Docker workspace mount",
    status: "Partial" as CapabilityStatus
  },
  {
    id: "plan",
    title: "Plan",
    meta: "profile checks, guardrails, evidence paths",
    status: "Ready" as CapabilityStatus
  },
  {
    id: "queue",
    title: "Queue",
    meta: "Redis-backed scan request",
    status: "Ready" as CapabilityStatus
  },
  {
    id: "run",
    title: "Run",
    meta: "worker/toolbox execution",
    status: "Partial" as CapabilityStatus
  },
  {
    id: "triage",
    title: "Triage",
    meta: "findings UI and exceptions",
    status: "Gap" as CapabilityStatus
  },
  {
    id: "export",
    title: "Export",
    meta: "reports and central envelope",
    status: "Partial" as CapabilityStatus
  }
];

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

async function fetchOptionalJson<T>(url: string, init?: RequestInit): Promise<T | null> {
  const response = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...init?.headers
    }
  });

  if (response.status === 404) {
    return null;
  }

  const payload = (await response.json()) as T & { error?: { message?: string } };

  if (!response.ok) {
    throw new Error(payload.error?.message ?? `Request failed with status ${response.status}`);
  }

  return payload;
}

function statusTone(status: string): BadgeTone {
  if (["Ready", "READY", "PASS", "pass", "completed", "available", "container", "success", "queued"].includes(status)) return "good";
  if (["Partial", "WARNING", "warning", "MEDIUM", "idle", "loading", "running"].includes(status)) return "warning";
  if (["Gap", "Blocked", "FAIL", "fail", "failed", "error", "HIGH", "missing", "blocked"].includes(status)) return "danger";
  return "neutral";
}

function statusRag(status: string): RagStatus {
  if (["Ready", "READY", "PASS", "pass", "completed", "available", "container", "success", "queued"].includes(status)) return "GREEN";
  if (["Partial", "WARNING", "warning", "MEDIUM", "idle", "loading", "running"].includes(status)) return "AMBER";
  if (["Gap", "Blocked", "FAIL", "fail", "failed", "error", "HIGH", "missing", "blocked"].includes(status)) return "RED";
  return "GRAY";
}

function statusLabel(status: string) {
  return status === "success" ? "Ready" : status === "error" ? "Error" : status;
}

function gateLabel(gate: string): string {
  return gate === "pass" ? "PASS" : gate === "warning" ? "WARNING" : gate === "fail" ? "FAIL" : gate === "error" ? "ERROR" : gate.toUpperCase();
}

function formatDateTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "not available";
}

function formatDuration(value: number | null): string {
  if (value == null) return "not available";
  if (value < 1000) return `${value} ms`;

  return `${Math.round(value / 1000)} s`;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export default function DashboardPage() {
  const [activeView, setActiveView] = useState<WorkspaceView>("dashboard");
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("documentation-compliance");
  const [doctor, setDoctor] = useState<ToolchainDoctor | null>(null);
  const [scanRuns, setScanRuns] = useState<ScanRunSummary[]>([]);
  const [selectedRun, setSelectedRun] = useState<ScanRunDetail | null>(null);
  const [loadingDoctor, setLoadingDoctor] = useState(false);
  const [loadingRuns, setLoadingRuns] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailMode, setDetailMode] = useState<DetailSurfaceMode>("sidebar");
  const [scanResult, setScanResult] = useState<ScanActionResult>({
    mode: "plan",
    status: "idle",
    message: "Ready to run a local scan through the Docker worker."
  });

  const selectedProfile = useMemo(
    () => profiles.find((profile) => profile.id === selectedProfileId),
    [profiles, selectedProfileId]
  );
  const healthcareDoctor = doctor
    ? {
        available: doctor.summary.healthcareAvailable ?? doctor.summary.available,
        missing: doctor.summary.healthcareMissing ?? doctor.summary.missing,
        error: doctor.summary.healthcareError ?? doctor.summary.error,
        optionalMissing: doctor.summary.optionalMissing ?? 0,
        optionalError: doctor.summary.optionalError ?? 0
      }
    : null;
  const renderedTools = doctor?.tools.length
    ? doctor.tools.map((tool) => ({
        name: tool.name,
        status: !tool.requiredForHealthcare && tool.status !== "available" ? "optional" : tool.status,
        version: tool.version ?? tool.message ?? "not reported"
      }))
    : fallbackTools;
  const scanRows = useMemo<ScanRow[]>(
    () =>
      scanRuns.map((run) => ({
        id: run.id,
        project: run.project.name,
        profile: run.profile.id,
        status: run.status,
        result: gateLabel(run.gateResult),
        findings: `${run.findingCount} total`,
        finished: formatDateTime(run.finishedAt ?? run.startedAt)
      })),
    [scanRuns]
  );
  const latestRun = selectedRun ?? scanRuns[0] ?? null;
  const filteredCapabilityRows = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return capabilityRows;

    return capabilityRows.filter((row) =>
      `${row.area} ${row.status} ${row.implemented} ${row.gap} ${row.priority}`.toLowerCase().includes(query)
    );
  }, [searchQuery]);
  const maturityScore = Math.round(
    (capabilityRows.filter((row) => row.status === "Ready").length * 100 +
      capabilityRows.filter((row) => row.status === "Partial").length * 55) /
      capabilityRows.length
  );
  const criticalGaps = capabilityRows.filter((row) => row.priority === "P0" && row.status !== "Ready").length;
  const scanGate = scanResult.status === "error" || scanResult.blocked ? "Blocked" : scanResult.status === "success" ? "Ready" : "Partial";

  const projectColumns = useMemo<Array<DataTableColumn<ProjectRow>>>(
    () => [
      {
        id: "project",
        label: "Project",
        width: "minmax(220px, 1.3fr)",
        sortable: true,
        sortAccessor: (row) => row.name,
        render: (row) => (
          <span className="security-cell-stack">
            <strong>{row.name}</strong>
            <small>{row.path}</small>
          </span>
        )
      },
      {
        id: "stack",
        label: "Stack",
        width: "minmax(170px, 1fr)",
        render: (row) => <span className="security-wrap">{row.stack}</span>
      },
      {
        id: "data",
        label: "Data",
        width: 132,
        render: (row) => <Badge tone={row.data === "health-data" ? "danger" : "neutral"}>{row.data}</Badge>
      },
      {
        id: "gate",
        label: "Gate",
        width: 110,
        render: (row) => <RagBadge status={statusRag(row.gate)} label={row.gate} />
      },
      {
        id: "findings",
        label: "Open",
        width: 140,
        render: (row) => row.findings
      }
    ],
    []
  );

  const scanColumns = useMemo<Array<DataTableColumn<ScanRow>>>(
    () => [
      {
        id: "project",
        label: "Project",
        width: "minmax(170px, 1fr)",
        sortable: true,
        sortAccessor: (row) => row.project,
        render: (row) => row.project
      },
      {
        id: "profile",
        label: "Profile",
        width: "minmax(220px, 1.2fr)",
        render: (row) => <code>{row.profile}</code>
      },
      {
        id: "status",
        label: "Status",
        width: 110,
        render: (row) => <Badge tone={statusTone(row.status)}>{row.status}</Badge>
      },
      {
        id: "result",
        label: "Result",
        width: 120,
        render: (row) => <RagBadge status={statusRag(row.result)} label={row.result} />
      },
      {
        id: "findings",
        label: "Findings",
        width: 120,
        render: (row) => row.findings
      },
      {
        id: "finished",
        label: "Finished",
        width: "minmax(170px, 1fr)",
        render: (row) => row.finished
      }
    ],
    []
  );

  const capabilityColumns = useMemo<Array<DataTableColumn<CapabilityRow>>>(
    () => [
      {
        id: "area",
        label: "Capability",
        width: "minmax(210px, 1fr)",
        sortable: true,
        sortAccessor: (row) => row.area,
        render: (row) => (
          <span className="security-cell-stack">
            <strong>{row.area}</strong>
            <small>{row.priority}</small>
          </span>
        )
      },
      {
        id: "status",
        label: "Status",
        width: 120,
        sortable: true,
        sortAccessor: (row) => row.status,
        render: (row) => <RagBadge status={statusRag(row.status)} label={row.status} />
      },
      {
        id: "implemented",
        label: "Implemented",
        width: "minmax(280px, 1.4fr)",
        render: (row) => <span className="security-wrap">{row.implemented}</span>
      },
      {
        id: "gap",
        label: "Gap",
        width: "minmax(320px, 1.6fr)",
        render: (row) => <span className="security-wrap">{row.gap}</span>
      }
    ],
    []
  );

  const navGroups = useMemo<WorkspaceNavGroup[]>(
    () => [
      {
        id: "workspace",
        label: "Workspace",
        items: [
          {
            id: "dashboard",
            label: "Dashboard",
            icon: <LayoutDashboard size={16} />,
            active: activeView === "dashboard"
          },
          {
            id: "capabilities",
            label: "Capability audit",
            icon: <Gauge size={16} />,
            badge: criticalGaps,
            active: activeView === "capabilities"
          },
          {
            id: "execution",
            label: "Execution",
            icon: <Activity size={16} />,
            active: activeView === "execution"
          },
          {
            id: "telemetry",
            label: "Telemetry",
            icon: <Database size={16} />,
            active: activeView === "telemetry"
          }
        ]
      },
      {
        id: "future",
        label: "Backlog surfaces",
        items: [
          {
            id: "findings",
            label: "Findings triage",
            icon: <FileWarning size={16} />,
            disabled: true,
            disabledReason: "Needs persisted findings UI and exception workflow."
          },
          {
            id: "reports",
            label: "Report browser",
            icon: <ScrollText size={16} />,
            disabled: true,
            disabledReason: "Basic evidence browser is in Execution; download and retention workflows are pending."
          }
        ]
      }
    ],
    [activeView, criticalGaps]
  );

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

  useEffect(() => {
    void refreshScanRuns();
  }, []);

  async function loadScanRunDetail(scanRunId: string): Promise<ScanRunDetail | null> {
    const payload = await fetchOptionalJson<{ data: ScanRunDetail }>(`${apiBaseUrl}/api/v1/scans/runs/${scanRunId}`);

    if (!payload) {
      return null;
    }

    setSelectedRun(payload.data);
    return payload.data;
  }

  async function refreshScanRuns(preferredScanRunId?: string) {
    setLoadingRuns(true);

    try {
      const payload = await fetchJson<{ data: ScanRunSummary[] }>(`${apiBaseUrl}/api/v1/scans/runs`);
      setScanRuns(payload.data);

      const nextScanRunId = preferredScanRunId ?? selectedRun?.id ?? payload.data[0]?.id;

      if (nextScanRunId) {
        await loadScanRunDetail(nextScanRunId);
      } else {
        setSelectedRun(null);
      }
    } catch (error) {
      setScanResult({
        mode: "plan",
        status: "error",
        message: error instanceof Error ? error.message : "Failed to load scan run history."
      });
    } finally {
      setLoadingRuns(false);
    }
  }

  async function pollScanRun(scanRunId: string) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await delay(1500);

      let detail: ScanRunDetail | null;

      try {
        detail = await loadScanRunDetail(scanRunId);
      } catch (error) {
        setScanResult((current) =>
          current.scanRunId === scanRunId
            ? {
                ...current,
                status: "error",
                message: error instanceof Error ? error.message : "Failed to load scan evidence."
              }
            : current
        );
        return;
      }

      if (detail) {
        await refreshScanRuns(scanRunId);
        setScanResult((current) =>
          current.scanRunId === scanRunId
            ? {
                ...current,
                status: "success",
                message: `Scan finished with ${gateLabel(detail.gateResult)} gate.`,
                gate: gateLabel(detail.gateResult),
                stepCount: detail.steps.length
              }
            : current
        );
        return;
      }

      setScanResult((current) =>
        current.scanRunId === scanRunId
          ? {
              ...current,
              message: "Scan job is queued; waiting for worker evidence."
            }
          : current
      );
    }

    await refreshScanRuns(scanRunId);
    setScanResult((current) =>
      current.scanRunId === scanRunId
        ? {
            ...current,
            message: "Scan job was queued, but evidence is not available yet."
          }
        : current
    );
  }

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

      if (mode === "queue") {
        void pollScanRun(scanRunId);
      }
    } catch (error) {
      setScanResult({
        mode,
        status: "error",
        message: error instanceof Error ? error.message : "Scan action failed.",
        scanRunId
      });
    }
  }

  function renderDashboard() {
    return (
      <div className="security-view-stack">
        <section className="security-metric-grid" aria-label="SecurityPreflight maturity summary">
          <MetricCard
            icon={ShieldCheck}
            label="Functional maturity"
            value={`${maturityScore}%`}
            detail={`${criticalGaps} P0 gaps remain before reference-grade healthcare use.`}
            tone={criticalGaps ? "warning" : "good"}
            chartData={[32, 38, 42, 48, maturityScore]}
          />
          <MetricCard
            icon={ClipboardList}
            label="Scan profiles"
            value={profiles.length || "-"}
            detail="Loaded from the local API contract."
            tone="info"
            chartData={[4, 5, 7, 8, profiles.length || 9]}
          />
          <MetricCard
            icon={Wrench}
            label="Toolchain"
            value={healthcareDoctor ? healthcareDoctor.available : "not checked"}
            detail={
              healthcareDoctor
                ? `${healthcareDoctor.missing} healthcare missing / ${healthcareDoctor.error} error${
                    healthcareDoctor.optionalMissing || healthcareDoctor.optionalError ? " / optional DAST gap" : ""
                  }`
                : "Run doctor to verify scanner availability."
            }
            tone={healthcareDoctor?.error || healthcareDoctor?.missing ? "danger" : doctor ? "good" : "neutral"}
            chartType="bar"
            chartData={healthcareDoctor ? [healthcareDoctor.available, healthcareDoctor.missing, healthcareDoctor.error] : undefined}
          />
          <MetricCard
            icon={FileJson}
            label="Central result envelope"
            value="v1"
            detail="OpenAPI ingest and redacted worker output exist."
            tone="warning"
            chartData={[1, 1, 1, 1, 1]}
          />
        </section>

        <DataGridShell
          title={<strong>Projects</strong>}
          toolbar={<Badge tone="warning">registry UI pending</Badge>}
          className="security-grid-shell"
        >
          <DataTable
            rows={projectRows}
            columns={projectColumns}
            getRowId={(row) => row.id}
            emptyLabel="No projects"
            aria-label="Registered projects"
          />
        </DataGridShell>

        <div className="security-split-grid">
          <DataGridShell
            title={<strong>Recent scan runs</strong>}
            toolbar={
              <Button disabled={loadingRuns} onClick={() => refreshScanRuns()} size="compact">
                <History size={14} />
                {loadingRuns ? "Refreshing" : "Refresh"}
              </Button>
            }
            className="security-grid-shell"
          >
            <DataTable
              rows={scanRows}
              columns={scanColumns}
              getRowId={(row) => row.id}
              emptyLabel="No completed scan evidence yet"
              aria-label="Recent scans"
            />
          </DataGridShell>

          <StructuredList
            title="Toolchain doctor"
            description={doctor ? `Checked ${new Date(doctor.checkedAt).toLocaleTimeString()}` : "Docker scanner stack"}
            count={
              <Badge tone={healthcareDoctor ? statusTone(healthcareDoctor.error || healthcareDoctor.missing ? "error" : "available") : "neutral"}>
                {doctor ? "live" : "fallback"}
              </Badge>
            }
            toolbar={
              <Button disabled={loadingDoctor} onClick={refreshDoctor} size="compact">
                <Wrench size={14} />
                {loadingDoctor ? "Checking" : "Check"}
              </Button>
            }
            items={renderedTools.map((tool) => ({
              id: tool.name,
              title: tool.name,
              leading: <Wrench size={15} />,
              badges: <Badge tone={statusTone(tool.status)}>{tool.status}</Badge>,
              meta: <code>{tool.version}</code>
            }))}
            ariaLabel="Toolchain doctor"
            className="security-list-card"
          />
        </div>
      </div>
    );
  }

  function renderCapabilities() {
    return (
      <div className="security-view-stack">
        <section className="security-analysis-panel">
          <div>
            <h2>Celková funkčnost</h2>
            <p>
              Aplikace má funkční lokální scan pipeline, OpenAPI kontrakt, worker evidence a centrální envelope. Produktově je
              ale stále na úrovni silnějšího MVP: největší mezery jsou persistentní registry projektů, triage findings,
              report browser, progress běhů a bezpečnostní hranice pro sdílené/centrální nasazení.
            </p>
          </div>
          <div className="security-progress-card">
            <span>Maturity estimate</span>
            <strong>{maturityScore}%</strong>
            <ProgressBar value={maturityScore} tone={criticalGaps ? "warning" : "good"} label="Functional maturity" />
          </div>
        </section>

        <DataGridShell
          title={<strong>Capability audit</strong>}
          toolbar={<Badge tone={criticalGaps ? "danger" : "good"}>{criticalGaps} P0 gaps</Badge>}
          className="security-grid-shell"
        >
          <DataTable
            rows={filteredCapabilityRows}
            columns={capabilityColumns}
            getRowId={(row) => row.id}
            emptyLabel="No matching capabilities"
            aria-label="Capability audit"
          />
        </DataGridShell>
      </div>
    );
  }

  function renderExecution() {
    return (
      <div className="security-view-stack">
        <StructuredList
          title="Execution lifecycle"
          description="Current end-to-end capability from local project to evidence"
          count={<Badge tone="warning">triage incomplete</Badge>}
          items={executionStages.map((stage) => ({
            id: stage.id,
            title: stage.title,
            leading: <RagBadge status={statusRag(stage.status)} label={stage.status} />,
            meta: stage.meta
          }))}
          ariaLabel="Execution lifecycle"
          className="security-list-card"
        />
        <DataGridShell title={<strong>Planned checks in selected profile</strong>} className="security-grid-shell">
          <StructuredList
            items={(selectedProfile?.checks ?? []).map((check) => ({
              id: check,
              title: check,
              leading: <CheckCircle2 size={15} />,
              badges: <Badge tone="info">planned</Badge>
            }))}
            emptyLabel="Load a scan profile to see planned checks."
            ariaLabel="Selected scan profile checks"
          />
        </DataGridShell>
        <div className="security-split-grid">
          <StructuredList
            title="Latest report evidence"
            description={latestRun ? `${latestRun.id} · ${formatDuration(latestRun.durationMs)}` : "Run a scan to create report evidence"}
            count={<Badge tone={latestRun ? statusTone(latestRun.gateResult) : "neutral"}>{latestRun ? gateLabel(latestRun.gateResult) : "empty"}</Badge>}
            toolbar={
              <Button disabled={loadingRuns} onClick={() => refreshScanRuns(latestRun?.id)} size="compact">
                <History size={14} />
                Refresh
              </Button>
            }
            items={(latestRun?.evidence.files ?? []).map((file) => ({
              id: file,
              title: file,
              leading: file.endsWith(".md") ? <ScrollText size={15} /> : <FileJson size={15} />,
              badges: <Badge tone={file === "central-result-envelope.json" ? "info" : "good"}>{file.endsWith(".json") ? "json" : "markdown"}</Badge>,
              meta: "REPORTS_PATH evidence"
            }))}
            emptyLabel="No evidence files found"
            ariaLabel="Latest report evidence"
            className="security-list-card"
          />
          <StructuredList
            title="Latest run steps"
            description={selectedRun ? `${selectedRun.findingCount} findings · finished ${formatDateTime(selectedRun.finishedAt)}` : "Select or run a scan to load step detail"}
            count={<Badge tone={selectedRun ? statusTone(selectedRun.status) : "neutral"}>{selectedRun?.status ?? "not loaded"}</Badge>}
            items={(selectedRun?.steps ?? []).map((step) => ({
              id: step.stepId,
              title: step.checkId,
              leading: <RagBadge status={statusRag(step.status)} label={step.status} />,
              badges: step.findingCount ? <Badge tone="danger">{step.findingCount} findings</Badge> : <Badge tone="good">0 findings</Badge>,
              meta: step.evidenceFile ?? step.message ?? "no evidence file"
            }))}
            emptyLabel="No step detail loaded"
            ariaLabel="Latest run steps"
            className="security-list-card"
          />
        </div>
      </div>
    );
  }

  function renderTelemetry() {
    return (
      <div className="security-view-stack">
        <section className="security-analysis-panel">
          <div>
            <h2>Telemetry and central storage</h2>
            <p>
              The API exposes a v1 central ingest contract and the worker writes a redacted result envelope. This is the
              right direction for sensitive healthcare projects, but production use still needs delivery status, signing,
              retention policy, and authenticated central intake.
            </p>
          </div>
          <Badge tone="warning">integration partial</Badge>
        </section>
        <StructuredList
          title="Central result envelope"
          description="Current contract and missing production controls"
          count={<Badge tone="info">OpenAPI v1</Badge>}
          items={[
            {
              id: "endpoint",
              title: "POST /api/v1/results/ingest",
              leading: <Database size={15} />,
              badges: <Badge tone="good">implemented</Badge>,
              meta: "contract-first ingest"
            },
            {
              id: "redaction",
              title: "Redacted worker envelope",
              leading: <FileJson size={15} />,
              badges: <Badge tone="good">implemented</Badge>,
              meta: "no raw source upload"
            },
            {
              id: "delivery",
              title: "Delivery status and retry queue",
              leading: <History size={15} />,
              badges: <Badge tone="warning">missing</Badge>,
              meta: "needed for central evidence"
            },
            {
              id: "auth",
              title: "Authenticated central intake",
              leading: <ShieldCheck size={15} />,
              badges: <Badge tone="danger">blocked</Badge>,
              meta: "required before shared deployment"
            }
          ]}
          ariaLabel="Central telemetry status"
          className="security-list-card"
        />
      </div>
    );
  }

  const renderedView =
    activeView === "capabilities"
      ? renderCapabilities()
      : activeView === "execution"
        ? renderExecution()
        : activeView === "telemetry"
          ? renderTelemetry()
          : renderDashboard();

  return (
    <AppShell
      className="security-shell"
      topbarPlacement="main"
      rail={
        <AppRail
          workspaceMark="SP"
          items={[
            { id: "security", label: "Security", icon: ShieldCheck },
            { id: "evidence", label: "Evidence", icon: Archive }
          ]}
          footerItems={[{ id: "settings", label: "Settings", icon: Settings, disabled: true, disabledReason: "Settings surface is backlog." }]}
          activeItemId={activeView === "execution" ? "evidence" : "security"}
          panelOpen
          onItemSelect={(itemId) => setActiveView(itemId === "evidence" ? "execution" : "dashboard")}
        />
      }
      sidebar={
        <WorkspaceSidebar
          title="SecurityPreflight"
          subtitle="STRATOS security workspace"
          footer={
            <div className="security-sidebar-footer">
              <Badge tone="good">local only</Badge>
              <span>API {apiBaseUrl.replace("http://", "")}</span>
            </div>
          }
        >
          <WorkspaceNav groups={navGroups} onSelect={(itemId) => setActiveView(itemId as WorkspaceView)} />
        </WorkspaceSidebar>
      }
      topbar={
        <Topbar
          breadcrumbs={[
            { id: "stratos", label: "STRATOS" },
            { id: "security-preflight", label: "SecurityPreflight" },
            { id: activeView, label: activeView === "capabilities" ? "Capability audit" : activeView }
          ]}
          search={
            <SearchBox
              value={searchQuery}
              onChange={setSearchQuery}
              onClear={() => setSearchQuery("")}
              placeholder="Search capabilities"
              variant="toolbar"
              ariaLabel="Search capabilities"
            />
          }
          actions={[
            {
              id: "doctor",
              label: loadingDoctor ? "Checking" : "Doctor",
              icon: <Wrench size={15} />,
              onClick: refreshDoctor,
              disabled: loadingDoctor
            },
            {
              id: "audit",
              label: "Audit",
              icon: <Gauge size={15} />,
              variant: "primary",
              onClick: () => {
                setActiveView("capabilities");
                setDetailOpen(true);
              }
            }
          ]}
          trailing={<RagBadge status={statusRag(scanGate)} label={scanGate} />}
        />
      }
      toolbar={
        <ViewToolbar
          leading={
            <ViewTabs
              tabs={[
                { id: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={15} /> },
                { id: "capabilities", label: "Capability audit", icon: <Gauge size={15} />, badge: <Badge tone="danger">{criticalGaps}</Badge> },
                { id: "execution", label: "Execution", icon: <Activity size={15} /> },
                { id: "telemetry", label: "Telemetry", icon: <Database size={15} /> }
              ]}
              activeTabId={activeView}
              onTabChange={(tabId) => setActiveView(tabId as WorkspaceView)}
            />
          }
          trailing={<Badge tone="warning">healthcare reference requires P0 gap closure</Badge>}
        />
      }
    >
      <div className="security-content">
        <section className="security-main">{renderedView}</section>

        <aside className="security-run-panel" aria-label="Run scan">
          <div className="security-run-header">
            <div>
              <h2>Run scan</h2>
              <span>{dockerProjectPath}</span>
            </div>
            <RagBadge status={statusRag(scanGate)} label={scanResult.gate ?? statusLabel(scanResult.status)} />
          </div>

          <SelectField
            label="Scan profile"
            value={selectedProfileId}
            onChange={(event) => setSelectedProfileId(event.currentTarget.value)}
            searchPlaceholder="Find profile"
          >
            {profiles.map((profile) => (
              <option key={profile.id} value={profile.id}>
                {profile.name}
              </option>
            ))}
          </SelectField>

          <p className="security-run-description">{selectedProfile?.description ?? "Load profiles from the local API to start scanning."}</p>

          <div className="security-facts">
            <div>
              <span>Project</span>
              <strong>SecurityPreflight</strong>
            </div>
            <div>
              <span>Checks</span>
              <strong>{selectedProfile?.checks.length ?? 0}</strong>
            </div>
            <div>
              <span>Tools</span>
              <strong>{healthcareDoctor ? `${healthcareDoctor.available} healthcare ready` : "not checked"}</strong>
            </div>
          </div>

          <div className="security-actions">
            <Button variant="primary" disabled={scanResult.status === "loading"} onClick={() => runScan("queue")}>
              <Play size={14} />
              Run scan
            </Button>
            <Button disabled={scanResult.status === "loading"} onClick={() => runScan("plan")}>
              <ClipboardList size={14} />
              Dry run
            </Button>
            <IconButton label="Open scan log" disabled title="Scan log UI is not implemented yet.">
              <TerminalSquare size={14} />
            </IconButton>
          </div>

          <div className="security-result" data-tone={statusTone(scanResult.status)} role="status">
            <strong>{scanResult.status === "loading" ? "Working" : statusLabel(scanResult.status)}</strong>
            <p>{scanResult.message}</p>
            {scanResult.scanRunId ? <code>{scanResult.scanRunId}</code> : null}
            {scanResult.stepCount != null ? <span>{scanResult.stepCount} planned steps</span> : null}
          </div>

          <Button className="security-wide-button" onClick={() => setDetailOpen(true)}>
            <AlertTriangle size={14} />
            Show maturity blockers
          </Button>
        </aside>
      </div>

      <DetailSurface
        open={detailOpen}
        mode={detailMode}
        title="SecurityPreflight functional audit"
        labels={{ close: "Close", sidebar: "Sidebar", modal: "Modal", fullscreen: "Fullscreen" }}
        onClose={() => setDetailOpen(false)}
        onModeChange={setDetailMode}
      >
        <div className="security-detail-stack">
          <section>
            <h2>Current assessment</h2>
            <p>
              SecurityPreflight is beyond a static scaffold, but still below reference-grade healthcare readiness. The scan
              execution path works; operational product depth is still incomplete around findings, evidence browsing,
              project registry, progress tracking, and central delivery guarantees.
            </p>
          </section>
          <StructuredList
            title="P0 blockers"
            items={capabilityRows
              .filter((row) => row.priority === "P0" && row.status !== "Ready")
              .map((row) => ({
                id: row.id,
                title: row.area,
                leading: <RagBadge status={statusRag(row.status)} label={row.status} />,
                meta: row.gap
              }))}
            ariaLabel="P0 blockers"
          />
        </div>
      </DetailSurface>
    </AppShell>
  );
}
