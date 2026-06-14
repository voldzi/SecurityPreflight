"use client";

import {
  Activity,
  AlertTriangle,
  Archive,
  Bot,
  CheckCircle2,
  ClipboardList,
  Database,
  Download,
  FileJson,
  FileText,
  FileWarning,
  FolderGit2,
  Gauge,
  History,
  LayoutDashboard,
  LogIn,
  LogOut,
  MessageSquareText,
  Play,
  Presentation,
  Search,
  ScrollText,
  Settings,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Wrench
} from "lucide-react";
import {
  AppRail,
  AppShell,
  Badge,
  Button,
  CommandCenter,
  DataGridShell,
  DataTable,
  DetailSurface,
  GlobalTopbar,
  IconButton,
  MetricCard,
  ProgressBar,
  RagBadge,
  SearchBox,
  SelectField,
  StructuredList,
  ViewTabs,
  ViewToolbar,
  WorkspaceNav,
  WorkspaceSidebar,
  buildStratosTopbarApps,
  type BadgeTone,
  type CommandCenterItem,
  type DataTableColumn,
  type DetailSurfaceMode,
  type RagStatus,
  type WorkspaceNavGroup
} from "@voldzi/stratos-ui";
import { useEffect, useMemo, useState } from "react";
import { completeOidcLogin, oidcConfig, oidcLogoutUrl, startOidcLogin, type OidcClientConfig } from "./oidc";

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

interface ReportExportPayload {
  reportType: "SECURITY_PREFLIGHT_SCAN";
  format: "PDF" | "PPTX";
  fileName: string;
  mimeType: string;
  encoding: "base64";
  content: string;
  contentHash: string;
  generatedAt: string;
}

interface AkbStatus {
  configured: boolean;
  ragConfigured: boolean;
  publicBaseUrl: string | null;
  authMode: "caller-bearer" | "oidc-client-credentials" | "service-token" | "none";
  syncRequired: boolean;
  boundaries: {
    storesPrompts: false;
    storesResponses: false;
    storesChunks: false;
    requiresCitations: true;
  };
}

interface AuthStatus {
  mode: "disabled" | "shared-token" | "oidc";
  required: boolean;
  configured: boolean;
  issuer: string | null;
  audience: string | null;
  clientId: string | null;
  requiredRoles: string[];
  operatorRoles: string[];
  publicOidc: {
    configured: boolean;
    issuer: string | null;
    clientId: string | null;
    scopes: string;
  };
}

interface AkbAnswer {
  provider: "AKB";
  scanRunId: string;
  answer: string;
  confidence: number | null;
  noAnswer: boolean;
  citations: Array<{
    chunkId: string | null;
    documentId: string | null;
    documentVersionId: string | null;
    title: string | null;
    page: number | null;
    sectionPath: string | null;
    openUrl: string | null;
  }>;
  warnings: string[];
  missingInformation: string[];
  usedSourceIds: string[];
  correlationId: string;
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
const authTokenStorageKey = "security-preflight.auth.token";
const stratosAppUrls = {
  "budget-contract": process.env.NEXT_PUBLIC_STRATOS_HOME_URL || "https://stratos.zeleznalady.cz/",
  projectflow: process.env.NEXT_PUBLIC_PROJECTFLOW_URL || "https://stratos.zeleznalady.cz/project",
  akb: process.env.NEXT_PUBLIC_AKB_URL || "https://stratos.zeleznalady.cz/akb",
  archflow: process.env.NEXT_PUBLIC_ARCHFLOW_URL,
  processforge: process.env.NEXT_PUBLIC_PROCESSFORGE_URL
};
const stratosTopbarApps = [
  { id: "security-preflight", label: "SecurityPreflight", shortLabel: "SP", icon: <ShieldCheck size={15} />, active: true },
  ...buildStratosTopbarApps("budget-contract", stratosAppUrls).map((app) => ({
    ...app,
    active: false,
    onSelect:
      !app.disabled && stratosAppUrls[app.id as keyof typeof stratosAppUrls]
        ? () => {
            window.location.assign(stratosAppUrls[app.id as keyof typeof stratosAppUrls] as string);
          }
        : app.onSelect
  }))
];

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
    status: "Ready",
    implemented: "Markdown, JSON, execution-result, central envelope, live evidence browser, and PDF/PPTX export workflow.",
    gap: "Add SARIF/SBOM export view and evidence retention controls.",
    priority: "P1"
  },
  {
    id: "akb-ai",
    area: "STRATOS AKB AI bridge",
    status: "Partial",
    implemented: "Server-side AKB RAG bridge with cited answers, no prompt/answer/chunk storage, and UI status panel.",
    gap: "Needs production AKB URL/OIDC configuration and contract tests against live AKB OpenAPI.",
    priority: "P0"
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
    status: "Partial",
    implemented: "API supports STRATOS OIDC/JWKS RBAC, shared-token transition mode, protected endpoints, and UI bearer handoff.",
    gap: "Production still needs Keycloak client/roles, TLS termination, and audit event persistence.",
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

async function fetchJson<T>(url: string, init?: RequestInit, authToken?: string | null): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...authHeaders(authToken),
      ...init?.headers
    }
  });
  const payload = (await response.json()) as T & { error?: { message?: string } };

  if (!response.ok) {
    throw new Error(payload.error?.message ?? `Request failed with status ${response.status}`);
  }

  return payload;
}

async function fetchOptionalJson<T>(url: string, init?: RequestInit, authToken?: string | null): Promise<T | null> {
  const response = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...authHeaders(authToken),
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

function authHeaders(authToken?: string | null): Record<string, string> {
  return authToken ? { authorization: `Bearer ${authToken}` } : {};
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

function downloadBase64File(fileName: string, mimeType: string, content: string): void {
  const binary = window.atob(content);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  const url = window.URL.createObjectURL(new Blob([bytes], { type: mimeType }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
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
  const [commandOpen, setCommandOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState("");
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailMode, setDetailMode] = useState<DetailSurfaceMode>("sidebar");
  const [exportingFormat, setExportingFormat] = useState<"PDF" | "PPTX" | null>(null);
  const [exportMessage, setExportMessage] = useState("PDF/PPTX exports use redacted report evidence only.");
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [authTokenInput, setAuthTokenInput] = useState("");
  const [authMessage, setAuthMessage] = useState("Authentication status has not been checked yet.");
  const [oidcClient, setOidcClient] = useState<OidcClientConfig | null>(null);
  const [akbStatus, setAkbStatus] = useState<AkbStatus | null>(null);
  const [akbQuestion, setAkbQuestion] = useState("Shrn vysledek posledniho skenu pro zdravotnicky audit a uved citace.");
  const [akbAnswer, setAkbAnswer] = useState<AkbAnswer | null>(null);
  const [akbLoading, setAkbLoading] = useState(false);
  const [akbMessage, setAkbMessage] = useState("AKB odpovedi se neukladaji v SecurityPreflight.");
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
  const authReady = authStatus ? !authStatus.required || Boolean(authToken) : false;
  const authLabel = authStatus?.required ? (authToken ? "Authenticated" : "Auth required") : "Local mode";
  const commandItems = useMemo<CommandCenterItem[]>(
    () => [
      {
        id: "view-dashboard",
        type: "dashboard",
        title: "Dashboard",
        subtitle: "SecurityPreflight overview",
        icon: <LayoutDashboard size={18} />,
        primaryAction: {
          id: "open",
          label: "Open",
          onSelect: () => setActiveView("dashboard")
        }
      },
      {
        id: "view-capabilities",
        type: "dashboard",
        title: "Capability audit",
        subtitle: `${criticalGaps} P0 gaps`,
        icon: <Gauge size={18} />,
        tone: criticalGaps ? "amber" : "green",
        primaryAction: {
          id: "open",
          label: "Open",
          onSelect: () => setActiveView("capabilities")
        }
      },
      {
        id: "view-execution",
        type: "report",
        title: "Execution and evidence",
        subtitle: latestRun ? latestRun.id : "No scan evidence loaded",
        icon: <Archive size={18} />,
        primaryAction: {
          id: "open",
          label: "Open",
          onSelect: () => setActiveView("execution")
        }
      },
      {
        id: "view-telemetry",
        type: "report",
        title: "Telemetry and AKB",
        subtitle: akbStatus?.configured ? "AKB configured" : "AKB not configured",
        icon: <Database size={18} />,
        tone: akbStatus?.configured ? "green" : "amber",
        primaryAction: {
          id: "open",
          label: "Open",
          onSelect: () => setActiveView("telemetry")
        }
      },
      {
        id: "action-run-scan",
        type: "action",
        title: "Run scan",
        subtitle: selectedProfileId,
        icon: <Play size={18} />,
        tone: "green",
        primaryAction: {
          id: "run",
          label: "Queue",
          disabled: !authReady,
          onSelect: () => void runScan("queue")
        }
      },
      {
        id: "action-dry-run",
        type: "action",
        title: "Dry-run scan plan",
        subtitle: selectedProfileId,
        icon: <ClipboardList size={18} />,
        primaryAction: {
          id: "plan",
          label: "Plan",
          disabled: !authReady,
          onSelect: () => void runScan("plan")
        }
      },
      {
        id: "action-export-pdf",
        type: "report",
        title: "Export latest report as PDF",
        subtitle: latestRun?.id ?? "No latest scan run",
        icon: <FileText size={18} />,
        tone: latestRun ? "blue" : "amber",
        primaryAction: {
          id: "export",
          label: "Export",
          disabled: !latestRun || !authReady,
          onSelect: () => void exportLatestRun("PDF")
        }
      },
      {
        id: "action-export-pptx",
        type: "report",
        title: "Export latest report as PPTX",
        subtitle: latestRun?.id ?? "No latest scan run",
        icon: <Presentation size={18} />,
        tone: latestRun ? "purple" : "amber",
        primaryAction: {
          id: "export",
          label: "Export",
          disabled: !latestRun || !authReady,
          onSelect: () => void exportLatestRun("PPTX")
        }
      }
    ],
    [akbStatus?.configured, authReady, criticalGaps, latestRun, selectedProfileId]
  );

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
            id: "execution",
            label: "Reports and exports",
            icon: <ScrollText size={16} />,
            active: activeView === "execution"
          }
        ]
      }
    ],
    [activeView, criticalGaps]
  );

  useEffect(() => {
    const config = oidcConfig();
    setOidcClient(config);

    const storedToken = window.localStorage.getItem(authTokenStorageKey);
    if (storedToken) {
      setAuthToken(storedToken);
      setAuthTokenInput("");
    }

    async function initializeAuth() {
      try {
        if (config) {
          const completedToken = await completeOidcLogin(config, new URLSearchParams(window.location.search));
          if (completedToken) {
            persistAuthToken(completedToken);
            setAuthMessage("STRATOS OIDC session established.");
          }
        }
      } catch (error) {
        setAuthMessage(error instanceof Error ? error.message : "OIDC login failed.");
      } finally {
        await refreshAuthStatus();
      }
    }

    void initializeAuth();
  }, []);

  useEffect(() => {
    let active = true;

    async function loadProfiles() {
      try {
        if (!authStatus) return;
        if (!authReady && authStatus.required) return;

        const payload = await fetchJson<{ data: ScanProfile[] }>(`${apiBaseUrl}/api/v1/scan-profiles`, undefined, authToken);

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
  }, [authReady, authStatus?.required, authToken, selectedProfileId]);

  useEffect(() => {
    if (authReady) {
      void refreshScanRuns();
    }
  }, [authReady, authToken]);

  useEffect(() => {
    if (authReady) {
      void refreshAkbStatus();
    }
  }, [authReady, authToken]);

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen(true);
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  async function refreshAuthStatus() {
    try {
      const payload = await fetchJson<{ data: AuthStatus }>(`${apiBaseUrl}/api/v1/auth/status`);
      setAuthStatus(payload.data);
      setAuthMessage(
        payload.data.required
          ? payload.data.configured
            ? "Authentication is required for API access."
            : "Authentication is required but not fully configured."
          : "Local development mode does not require API authentication."
      );
    } catch (error) {
      setAuthStatus(null);
      setAuthMessage(error instanceof Error ? error.message : "Authentication status is not available.");
    }
  }

  function persistAuthToken(token: string) {
    const trimmed = token.trim();
    if (!trimmed) return;

    window.localStorage.setItem(authTokenStorageKey, trimmed);
    setAuthToken(trimmed);
    setAuthTokenInput("");
  }

  function clearAuthToken() {
    window.localStorage.removeItem(authTokenStorageKey);
    setAuthToken(null);
    setAuthTokenInput("");
    setAuthMessage("Authentication token cleared.");
    setProfiles([]);
    setScanRuns([]);
    setSelectedRun(null);
  }

  async function signInWithOidc() {
    if (!oidcClient) {
      setAuthMessage("STRATOS OIDC client is not configured.");
      return;
    }

    await startOidcLogin(oidcClient);
  }

  function signOut() {
    const logoutUrl = oidcClient ? oidcLogoutUrl(oidcClient) : null;
    clearAuthToken();

    if (logoutUrl && authStatus?.mode === "oidc") {
      window.location.assign(logoutUrl);
    }
  }

  async function loadScanRunDetail(scanRunId: string): Promise<ScanRunDetail | null> {
    const payload = await fetchOptionalJson<{ data: ScanRunDetail }>(`${apiBaseUrl}/api/v1/scans/runs/${scanRunId}`, undefined, authToken);

    if (!payload) {
      return null;
    }

    setSelectedRun(payload.data);
    return payload.data;
  }

  async function refreshScanRuns(preferredScanRunId?: string) {
    setLoadingRuns(true);

    try {
      const payload = await fetchJson<{ data: ScanRunSummary[] }>(`${apiBaseUrl}/api/v1/scans/runs`, undefined, authToken);
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
    if (!authReady) {
      setScanResult({
        mode: "plan",
        status: "error",
        message: "Authentication is required before checking the toolchain."
      });
      return;
    }

    setLoadingDoctor(true);

    try {
      const payload = await fetchJson<ToolchainDoctor>(`${apiBaseUrl}/api/v1/toolchain/doctor`, undefined, authToken);
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

  async function refreshAkbStatus() {
    try {
      const payload = await fetchJson<{ data: AkbStatus }>(`${apiBaseUrl}/api/v1/akb/status`, undefined, authToken);
      setAkbStatus(payload.data);
    } catch (error) {
      setAkbStatus(null);
      setAkbMessage(error instanceof Error ? error.message : "AKB status is not available.");
    }
  }

  async function exportLatestRun(format: "PDF" | "PPTX") {
    if (!authReady) {
      setExportMessage("Authentication is required before exporting reports.");
      return;
    }

    if (!latestRun) {
      setExportMessage("No scan run evidence is loaded yet.");
      return;
    }

    setExportingFormat(format);
    setExportMessage(`Generating ${format} export...`);

    try {
      const payload = await fetchJson<{ data: ReportExportPayload }>(`${apiBaseUrl}/api/v1/reports/export`, {
        method: "POST",
        body: JSON.stringify({
          scanRunId: latestRun.id,
          format,
          locale: "cs"
        })
      }, authToken);

      downloadBase64File(payload.data.fileName, payload.data.mimeType, payload.data.content);
      setExportMessage(`${format} export generated: ${payload.data.fileName}`);
    } catch (error) {
      setExportMessage(error instanceof Error ? error.message : `${format} export failed.`);
    } finally {
      setExportingFormat(null);
    }
  }

  async function askAkb() {
    if (!authReady) {
      setAkbMessage("Authentication is required before asking AKB.");
      return;
    }

    if (!latestRun) {
      setAkbMessage("No scan run evidence is loaded yet.");
      return;
    }

    setAkbLoading(true);
    setAkbAnswer(null);
    setAkbMessage("Asking AKB with scan-run scoped metadata and required citations...");

    try {
      const payload = await fetchJson<{ data: AkbAnswer }>(`${apiBaseUrl}/api/v1/akb/ai/ask`, {
        method: "POST",
        body: JSON.stringify({
          scanRunId: latestRun.id,
          question: akbQuestion,
          answerMode: "security_preflight_brief",
          responseLanguage: "cs"
        })
      }, authToken);

      setAkbAnswer(payload.data);
      setAkbMessage(payload.data.noAnswer ? "AKB returned an explicit no-answer." : "AKB returned a cited response.");
    } catch (error) {
      setAkbMessage(error instanceof Error ? error.message : "AKB request failed.");
    } finally {
      setAkbLoading(false);
    }
  }

  async function runScan(mode: "plan" | "queue") {
    if (!authReady) {
      setScanResult({
        mode,
        status: "error",
        message: "Authentication is required before running scans."
      });
      return;
    }

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
      }, authToken);
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
            label="Reports"
            value="PDF/PPTX"
            detail="STRATOS-style redacted exports plus central envelope v1."
            tone="good"
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
              Aplikace má funkční lokální scan pipeline, OpenAPI kontrakt, worker evidence, report exporty a AKB bridge podle
              STRATOS hranic. Největší mezery zůstávají persistentní registry projektů, triage findings, progress běhů,
              produkční AKB/OIDC konfigurace a bezpečnostní hranice pro sdílené nasazení.
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
              <span className="security-toolbar-actions">
                <Button disabled={loadingRuns} onClick={() => refreshScanRuns(latestRun?.id)} size="compact">
                  <History size={14} />
                  Refresh
                </Button>
                <IconButton
                  disabled={!latestRun || exportingFormat !== null || !authReady}
                  label="Export latest report as PDF"
                  size="compact"
                  title="Export redacted PDF report"
                  onClick={() => exportLatestRun("PDF")}
                >
                  <FileText size={14} />
                </IconButton>
                <IconButton
                  disabled={!latestRun || exportingFormat !== null || !authReady}
                  label="Export latest report as PPTX"
                  size="compact"
                  title="Export redacted PPTX report"
                  onClick={() => exportLatestRun("PPTX")}
                >
                  <Presentation size={14} />
                </IconButton>
              </span>
            }
            items={(latestRun?.evidence.files ?? []).map((file) => ({
              id: file,
              title: file,
              leading: file.endsWith(".md") ? <ScrollText size={15} /> : <FileJson size={15} />,
              badges: <Badge tone={file === "central-result-envelope.json" ? "info" : "good"}>{file.endsWith(".json") ? "json" : "markdown"}</Badge>,
              meta: "REPORTS_PATH evidence",
              actions: latestRun ? (
                <span className="security-hover-actions">
                  <IconButton
                    disabled={exportingFormat !== null || !authReady}
                    label={`Export ${file} report as PDF`}
                    size="compact"
                    title="Export scan run as PDF"
                    onClick={() => exportLatestRun("PDF")}
                  >
                    <Download size={13} />
                  </IconButton>
                  <IconButton
                    disabled={exportingFormat !== null || !authReady}
                    label={`Export ${file} report as PPTX`}
                    size="compact"
                    title="Export scan run as PPTX"
                    onClick={() => exportLatestRun("PPTX")}
                  >
                    <Presentation size={13} />
                  </IconButton>
                </span>
              ) : null
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
        <div className="security-result" data-tone={exportingFormat ? "warning" : "good"} role="status">
          <strong>{exportingFormat ? `Exporting ${exportingFormat}` : "Report exports"}</strong>
          <p>{exportMessage}</p>
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
              badges: <Badge tone={authStatus?.required ? "good" : "warning"}>{authStatus?.mode ?? "unknown"}</Badge>,
              meta: authStatus?.configured ? "protected API boundary available" : "authentication configuration incomplete"
            }
          ]}
          ariaLabel="Central telemetry status"
          className="security-list-card"
        />
        <StructuredList
          title="Access control"
          description="STRATOS OIDC and production API boundary"
          count={<Badge tone={authReady ? "good" : authStatus?.required ? "danger" : "warning"}>{authLabel}</Badge>}
          toolbar={
            <span className="security-toolbar-actions">
              {oidcClient ? (
                <Button disabled={Boolean(authToken)} onClick={signInWithOidc} size="compact">
                  <LogIn size={14} />
                  Sign in
                </Button>
              ) : null}
              {authToken ? (
                <Button onClick={signOut} size="compact">
                  <LogOut size={14} />
                  Sign out
                </Button>
              ) : null}
            </span>
          }
          items={[
            {
              id: "mode",
              title: "API authentication mode",
              leading: <ShieldCheck size={15} />,
              badges: <Badge tone={authStatus?.configured ? "good" : "danger"}>{authStatus?.mode ?? "unknown"}</Badge>,
              meta: authStatus?.issuer ?? "shared token or local development"
            },
            {
              id: "roles",
              title: "RBAC roles",
              leading: <FileJson size={15} />,
              badges: <Badge tone="info">{authStatus?.operatorRoles.length ?? 0} operator roles</Badge>,
              meta: authStatus?.operatorRoles.join(", ") || "not loaded"
            },
            {
              id: "cors",
              title: "Browser API boundary",
              leading: <Archive size={15} />,
              badges: <Badge tone="good">CORS allowlist</Badge>,
              meta: apiBaseUrl
            }
          ]}
          ariaLabel="Access control status"
          className="security-list-card"
        />
        {authStatus?.required && !authToken ? (
          <DataGridShell title={<strong>API bearer session</strong>} className="security-grid-shell">
            <div className="security-auth-panel">
              <label className="security-akb-question">
                <span>Bearer token</span>
                <input
                  value={authTokenInput}
                  onChange={(event) => setAuthTokenInput(event.currentTarget.value)}
                  type="password"
                  autoComplete="off"
                />
              </label>
              <div className="security-actions">
                <Button variant="primary" disabled={!authTokenInput.trim()} onClick={() => persistAuthToken(authTokenInput)}>
                  <ShieldCheck size={14} />
                  Use token
                </Button>
                {oidcClient ? (
                  <Button onClick={signInWithOidc}>
                    <LogIn size={14} />
                    STRATOS OIDC
                  </Button>
                ) : null}
              </div>
              <div className="security-result" data-tone={authStatus.configured ? "warning" : "danger"} role="status">
                <strong>{authStatus.configured ? "Protected API" : "Auth configuration incomplete"}</strong>
                <p>{authMessage}</p>
              </div>
            </div>
          </DataGridShell>
        ) : null}
        <div className="security-split-grid">
          <StructuredList
            title="AKB integration"
            description="Document-grounded AI boundary for STRATOS"
            count={<Badge tone={akbStatus?.configured ? "good" : "warning"}>{akbStatus?.configured ? "configured" : "not configured"}</Badge>}
            toolbar={
              <Button onClick={refreshAkbStatus} size="compact">
                <Bot size={14} />
                Refresh
              </Button>
            }
            items={[
              {
                id: "rag",
                title: "AKB RAG endpoint",
                leading: <MessageSquareText size={15} />,
                badges: <Badge tone={akbStatus?.ragConfigured ? "good" : "warning"}>{akbStatus?.ragConfigured ? "ready" : "missing"}</Badge>,
                meta: akbStatus?.publicBaseUrl ?? "set SECURITY_PREFLIGHT_AKB_RAG_BASE_URL"
              },
              {
                id: "auth",
                title: "Authentication mode",
                leading: <ShieldCheck size={15} />,
                badges: <Badge tone={akbStatus?.authMode === "none" ? "warning" : "good"}>{akbStatus?.authMode ?? "unknown"}</Badge>,
                meta: "caller bearer, OIDC client credentials, or service token"
              },
              {
                id: "boundaries",
                title: "SecurityPreflight storage boundary",
                leading: <Archive size={15} />,
                badges: <Badge tone="good">no local AI storage</Badge>,
                meta: "prompts, responses, chunks and embeddings stay in AKB"
              },
              {
                id: "citations",
                title: "Citations required",
                leading: <FileJson size={15} />,
                badges: <Badge tone="good">require_citations</Badge>,
                meta: "no-answer is machine-readable"
              }
            ]}
            ariaLabel="AKB integration status"
            className="security-list-card"
          />

          <DataGridShell
            title={<strong>Ask AKB about latest scan</strong>}
            toolbar={<Badge tone={akbStatus?.configured ? "good" : "warning"}>{latestRun?.id ?? "no scan"}</Badge>}
            className="security-grid-shell"
          >
            <div className="security-akb-panel">
              <label className="security-akb-question">
                <span>Question</span>
                <textarea
                  value={akbQuestion}
                  onChange={(event) => setAkbQuestion(event.currentTarget.value)}
                  rows={4}
                />
              </label>
              <div className="security-actions">
                <Button variant="primary" disabled={!latestRun || akbLoading || !authReady} onClick={askAkb}>
                  <Sparkles size={14} />
                  {akbLoading ? "Asking AKB" : "Ask AKB"}
                </Button>
                <Button disabled={akbLoading} onClick={() => setAkbQuestion("Jake jsou hlavni bezpecnostni zavery posledniho skenu a jake evidence je podporuji?")}>
                  <MessageSquareText size={14} />
                  Audit prompt
                </Button>
              </div>
              <div className="security-result" data-tone={akbAnswer ? "good" : akbStatus?.configured ? "warning" : "danger"} role="status">
                <strong>{akbAnswer ? "AKB response" : "AKB status"}</strong>
                <p>{akbAnswer?.answer ?? akbMessage}</p>
                {akbAnswer?.confidence != null ? <span>confidence {Math.round(akbAnswer.confidence * 100)}%</span> : null}
              </div>
              {akbAnswer?.citations.length ? (
                <StructuredList
                  title="Citations"
                  items={akbAnswer.citations.map((citation, index) => ({
                    id: citation.chunkId ?? `citation-${index}`,
                    title: citation.title ?? citation.documentId ?? "AKB citation",
                    leading: <FileJson size={15} />,
                    badges: <Badge tone="info">{citation.page ? `page ${citation.page}` : "source"}</Badge>,
                    meta: citation.sectionPath ?? citation.openUrl ?? citation.chunkId ?? "citation context"
                  }))}
                  ariaLabel="AKB citations"
                />
              ) : null}
            </div>
          </DataGridShell>
        </div>
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
      topbarPlacement="global"
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
        <GlobalTopbar
          apps={stratosTopbarApps}
          labels={{ applications: "STRATOS applications", userMenu: "User menu", settings: "Settings", logout: "Logout" }}
          context={<span>SecurityPreflight / {activeView === "capabilities" ? "Capability audit" : activeView}</span>}
          center={
            <button type="button" className="security-command-trigger" onClick={() => setCommandOpen(true)}>
              <Search size={15} />
              <span>Command Center</span>
              <kbd>Ctrl K</kbd>
            </button>
          }
          status={<RagBadge status={statusRag(scanGate)} label={scanGate} />}
          actions={
            <div className="security-topbar-actions">
              <Button disabled={loadingDoctor || !authReady} onClick={refreshDoctor} size="compact">
                <Wrench size={14} />
                {loadingDoctor ? "Checking" : "Doctor"}
              </Button>
              <Button
                variant="primary"
                onClick={() => {
                  setActiveView("capabilities");
                  setDetailOpen(true);
                }}
                size="compact"
              >
                <Gauge size={14} />
                Audit
              </Button>
            </div>
          }
          user={{ name: "Security analyst", initials: "SA", status: authLabel }}
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
          trailing={
            <span className="security-view-toolbar-trailing">
              <SearchBox
                value={searchQuery}
                onChange={setSearchQuery}
                onClear={() => setSearchQuery("")}
                placeholder="Filter capabilities"
                variant="toolbar"
                ariaLabel="Filter capabilities"
              />
              <Badge tone="warning">healthcare reference requires P0 gap closure</Badge>
            </span>
          }
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
            <Button variant="primary" disabled={scanResult.status === "loading" || !authReady} onClick={() => runScan("queue")}>
              <Play size={14} />
              Run scan
            </Button>
            <Button disabled={scanResult.status === "loading" || !authReady} onClick={() => runScan("plan")}>
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
              SecurityPreflight is beyond a static scaffold: scan execution, evidence browsing, PDF/PPTX exports and the
              AKB bridge are wired. Reference-grade healthcare readiness still needs findings triage, project registry,
              progress tracking, authenticated shared deployment and central delivery guarantees.
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
      <CommandCenter
        open={commandOpen}
        query={commandQuery}
        items={commandItems}
        labels={{
          title: "SecurityPreflight Command Center",
          placeholder: "Search views, reports and actions",
          noResults: "No matching action",
          open: "Open",
          close: "Close",
          actions: "Actions",
          preview: "STRATOS command surface for navigation, scan execution and report exports."
        }}
        onQueryChange={setCommandQuery}
        onClose={() => setCommandOpen(false)}
      />
    </AppShell>
  );
}
