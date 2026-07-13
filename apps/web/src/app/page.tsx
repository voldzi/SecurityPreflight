"use client";

import {
  Activity,
  AlertTriangle,
  Archive,
  Bot,
  CheckCircle2,
  ChevronRight,
  ChevronsLeft,
  ClipboardList,
  Database,
  Download,
  FileJson,
  FileText,
  FileWarning,
  FolderGit2,
  Gauge,
  Globe2,
  History,
  LayoutDashboard,
  LogIn,
  LogOut,
  MessageSquareText,
  Play,
  Presentation,
  RefreshCw,
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
  ErrorState,
  FieldLabelWithHelp,
  GlobalTopbar,
  HelpHint,
  IconButton,
  InformationPolicyPanel,
  MetricCard,
  ProgressBar,
  ProjectPicker,
  RagBadge,
  SearchBox,
  SelectField,
  SettingsChoiceGroup,
  SettingsField,
  SettingsTextInput,
  SettingsToggle,
  StratosSettingsSurface,
  StructuredList,
  WorkspaceSidebar,
  buildStratosTopbarApps,
  type BadgeTone,
  type CommandCenterItem,
  type DataTableColumn,
  type DetailSurfaceMode,
  type ProjectPickerProject,
  type RagStatus,
  type SettingsContentSection,
  type SettingsNavItem,
  type SettingsSurfaceMode,
  type StratosSettingsCoreValue,
  type StratosSettingsCoreValueKey,
  type StratosSettingsCoreValues,
  type WorkspaceNavGroup
} from "@voldzi/stratos-ui";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  defaultLocale,
  localeStorageKey,
  localizedCapabilityRows,
  localizedExecutionStages,
  localizedFallbackTools,
  profileDescription,
  profileName,
  translateGate,
  translateStatus,
  uiText,
  type AppLocale,
  type CapabilityRow,
  type CapabilityStatus
} from "./i18n";
import { completeOidcLogin, oidcConfig, oidcLogoutUrl, startOidcLogin, type OidcClientConfig } from "./oidc";
import { ScanProgressPanel } from "./components/ScanProgressPanel";
import { projectPolicyDetails, type ProjectPolicyBinding } from "./information-policy";

type WorkspaceView = "new-scan" | "dashboard" | "capabilities" | "execution" | "telemetry";
type RailPanel = "security" | "evidence";
type ScanTargetMode = "project" | "web";
type FindingTriageStatus = "open" | "accepted" | "false-positive" | "fixed" | "suppressed";
type SecuritySettingsTheme = "auto" | "light" | "dark";

interface SecuritySettingsDraft {
  displayName: string;
  email: string;
  role: string;
  language: AppLocale;
  timezone: string;
  theme: SecuritySettingsTheme;
  accent: string;
  highContrast: boolean;
  notifyTimezone: boolean;
  weekStart: "monday" | "sunday";
  timeFormat: "24h" | "12h";
  dateFormat: "dd.mm.yyyy" | "mm/dd/yyyy" | "yyyy-mm-dd";
  compactMode: boolean;
  commandHints: boolean;
  flyoutToasts: boolean;
  markdown: boolean;
  keyboardShortcuts: boolean;
  defaultProfileId: string;
  activeDastGuardrails: boolean;
  centralTelemetry: boolean;
  requireHealthDataProfile: boolean;
  twoFactor: boolean;
  password: string;
}

const defaultViewByRailPanel: Record<RailPanel, WorkspaceView> = {
  security: "new-scan",
  evidence: "execution"
};

const railPanelByWorkspaceView: Record<WorkspaceView, RailPanel> = {
  "new-scan": "security",
  dashboard: "security",
  capabilities: "security",
  execution: "evidence",
  telemetry: "evidence"
};

function isWorkspaceView(itemId: string): itemId is WorkspaceView {
  return itemId === "new-scan" || itemId === "dashboard" || itemId === "capabilities" || itemId === "execution" || itemId === "telemetry";
}

interface ScanProfile {
  id: string;
  name: string;
  description: string;
  checks: string[];
  allowActiveDast: boolean;
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
  blockedReasons?: string[];
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
    hasSarifReport: boolean;
    hasCentralTelemetryDelivery: boolean;
    hasDefectDojoDelivery: boolean;
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
    scope?: string;
    severity: string;
    title: string;
    filePath: string | null;
    line: number | null;
    endpoint: string | null;
    status: string;
    recommendation: string;
    triageStatus: FindingTriageStatus;
    triageNote: string | null;
    triageOwner: string | null;
    triageDueAt: string | null;
    triageExpiresAt: string | null;
    triageUpdatedAt: string | null;
    triageUpdatedBy: string | null;
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

interface ScanRunProgress {
  scanRunId: string;
  status: string;
  gateResult: string;
  totalSteps: number;
  completedSteps: number;
  failedSteps: number;
  blockedSteps: number;
  findingCount: number;
  startedAt: string | null;
  finishedAt: string | null;
  updatedAt: string | null;
  events: Array<{
    type: string;
    message: string | null;
    createdAt: string;
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

interface CodexRemediationExportPayload {
  reportType: "SECURITY_PREFLIGHT_CODEX_REMEDIATION";
  format: "MARKDOWN";
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

interface ScanRow {
  id: string;
  project: string;
  profile: string;
  status: string;
  result: string;
  findings: string;
  finished: string;
}

interface ProjectRow {
  id: string;
  name: string;
  path: string;
  stack: string;
  data: string;
  dataClassification: RegisteredProject["dataClassification"];
  owner: string;
  updatedAt: string;
}

interface RegisteredProject {
  id: string;
  name: string;
  path: string;
  repositoryUrl: string | null;
  publicUrl: string | null;
  defaultBranch: string | null;
  technologyStack: string[];
  dataClassification: "public" | "internal" | "confidential" | "sensitive" | "health-data";
  policyBinding?: ProjectPolicyBinding;
  owner: string | null;
  createdAt: string;
  updatedAt: string;
}

interface CapabilityAuditSignal {
  id: string;
  value?: string | number | boolean;
  total?: number;
}

interface CapabilityAuditRow {
  id: string;
  status: CapabilityStatus;
  priority: string;
  evidence: CapabilityAuditSignal[];
  gaps: CapabilityAuditSignal[];
}

interface CapabilityAudit {
  generatedAt: string;
  maturityScore: number;
  criticalGaps: number;
  rows: CapabilityAuditRow[];
}

const apiBaseUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8781";
const dockerProjectPath = "/workspace/projects";
const authTokenStorageKey = "security-preflight.auth.token";
const oidcAutoLoginStartedKey = "security-preflight.oidc.autoLoginStarted";
const oidcSkipAutoLoginKey = "security-preflight.oidc.skipAutoLogin";
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

class ApiRequestError extends Error {
  constructor(
    message: string,
    readonly statusCode: number,
    readonly code: string | null,
    readonly details: unknown[] | null = null
  ) {
    super(message);
    this.name = "ApiRequestError";
  }
}

async function fetchJson<T>(url: string, init?: RequestInit, authToken?: string | null): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...authHeaders(authToken),
      ...init?.headers
    }
  });
  const payload = (await response.json()) as T & { error?: { code?: string; message?: string; details?: unknown[] } };

  if (!response.ok) {
    throw new ApiRequestError(
      payload.error?.message ?? `Request failed with status ${response.status}`,
      response.status,
      payload.error?.code ?? null,
      Array.isArray(payload.error?.details) ? payload.error.details : null
    );
  }

  return payload;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function extractBlockedReasons(plan: unknown): string[] {
  if (!isRecord(plan)) return [];

  const directReasons = Array.isArray(plan.blockedReasons) ? plan.blockedReasons.filter((reason): reason is string => typeof reason === "string") : [];
  const stepReasons = Array.isArray(plan.steps)
    ? plan.steps.flatMap((step) => {
        if (!isRecord(step) || !Array.isArray(step.blockedReasons)) return [];
        return step.blockedReasons.filter((reason): reason is string => typeof reason === "string");
      })
    : [];

  return [...new Set([...directReasons, ...stepReasons])];
}

function scanPlanFromApiError(error: ApiRequestError): Record<string, unknown> | null {
  const plan = error.details?.find((detail) => isRecord(detail) && (detail.blocked === true || Array.isArray(detail.steps)));
  return isRecord(plan) ? plan : null;
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

  const payload = (await response.json()) as T & { error?: { code?: string; message?: string } };

  if (!response.ok) {
    throw new ApiRequestError(payload.error?.message ?? `Request failed with status ${response.status}`, response.status, payload.error?.code ?? null);
  }

  return payload;
}

function authHeaders(authToken?: string | null): Record<string, string> {
  return authToken ? { authorization: `Bearer ${authToken}` } : {};
}

function isAuthenticationFailure(error: unknown): boolean {
  return error instanceof ApiRequestError && error.statusCode === 401;
}

function isAuthorizationFailure(error: unknown): boolean {
  return error instanceof ApiRequestError && error.statusCode === 403;
}

function hostFromUrl(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return null;
    }
    return url.hostname.toLowerCase();
  } catch {
    return null;
  }
}

function statusTone(status: string): BadgeTone {
  if (["Ready", "READY", "PASS", "pass", "completed", "available", "container", "success", "queued"].includes(status)) return "good";
  if (["Partial", "WARNING", "warning", "MEDIUM", "idle", "loading", "running"].includes(status)) return "warning";
  if (["Gap", "Blocked", "FAIL", "fail", "failed", "error", "HIGH", "missing", "blocked"].includes(status)) return "danger";
  return "neutral";
}

function userFacingErrorMessage(error: unknown, fallback: string): string {
  if (!(error instanceof Error)) {
    return fallback;
  }

  const rawMessage = error.message.trim();
  if (!rawMessage) {
    return fallback;
  }

  if (error instanceof ApiRequestError) {
    const technicalStatus = error.statusCode === 401 || error.statusCode === 403 || error.statusCode >= 500;
    const technicalCode = /auth|jwt|oidc|token|bearer|json|payload/i.test(error.code ?? "");
    if (technicalStatus || technicalCode) {
      return fallback;
    }
  }

  if (/(jwt|oidc|bearer|token|authorization|unauthori[sz]ed|forbidden|401|403|json|payload|unexpected token|syntaxerror)/i.test(rawMessage)) {
    return fallback;
  }

  return rawMessage;
}

function statusRag(status: string): RagStatus {
  if (["Ready", "READY", "PASS", "pass", "completed", "available", "container", "success", "queued"].includes(status)) return "GREEN";
  if (["Partial", "WARNING", "warning", "MEDIUM", "idle", "loading", "running"].includes(status)) return "AMBER";
  if (["Gap", "Blocked", "FAIL", "fail", "failed", "error", "HIGH", "missing", "blocked"].includes(status)) return "RED";
  return "GRAY";
}

function statusDisplayLabel(status: string, locale: AppLocale): string {
  return translateStatus(locale, status);
}

function gateLabel(gate: string): string {
  return gate === "pass" ? "PASS" : gate === "warning" ? "WARNING" : gate === "fail" ? "FAIL" : gate === "error" ? "ERROR" : gate.toUpperCase();
}

function gateDisplayLabel(gate: string, locale: AppLocale): string {
  return translateGate(locale, gateLabel(gate));
}

function actionGateDisplayLabel(gate: string, locale: AppLocale): string {
  const normalized = gate.toLowerCase();
  if (["queued", "blocked", "ready"].includes(normalized)) {
    return translateStatus(locale, normalized);
  }

  return gateDisplayLabel(gate, locale);
}

function formatDateTime(value: string | null, locale: AppLocale): string {
  return value ? new Date(value).toLocaleString(locale === "cs" ? "cs-CZ" : "en-US") : uiText[locale].dates.notAvailable;
}

function formatDuration(value: number | null, locale: AppLocale): string {
  if (value == null) return uiText[locale].dates.notAvailable;
  if (value < 1000) return `${value} ms`;

  return `${Math.round(value / 1000)} s`;
}

function completedStepCount(steps: ScanRunDetail["steps"]): number {
  return steps.filter((step) => !["queued", "running", "loading", "pending"].includes(step.status.toLowerCase())).length;
}

function progressValue(completed: number, total: number, status?: string): number {
  if (!total) return status === "completed" ? 100 : 0;

  return Math.min(100, Math.round((completed / total) * 100));
}

function mergeCapabilityAuditRows(baseRows: CapabilityRow[], audit: CapabilityAudit | null, locale: AppLocale): CapabilityRow[] {
  if (!audit) return baseRows;

  const runtimeRows = new Map(audit.rows.map((row) => [row.id, row]));

  return baseRows.map((row) => {
    const runtime = runtimeRows.get(row.id);
    if (!runtime) return row;

    return {
      ...row,
      status: runtime.status,
      priority: runtime.priority || row.priority,
      implemented: runtime.evidence.length
        ? runtime.evidence.map((signal) => capabilitySignalLabel(signal, locale)).join("; ")
        : row.implemented,
      gap: runtime.gaps.length
        ? runtime.gaps.map((signal) => capabilitySignalLabel(signal, locale)).join("; ")
        : locale === "cs"
          ? "Bez otevřené mezery podle měřeného readiness auditu."
          : "No open gap in the measured readiness audit."
    };
  });
}

function capabilitySignalLabel(signal: CapabilityAuditSignal, locale: AppLocale): string {
  const value = capabilitySignalValue(signal, locale);

  const labels: Record<string, { cs: string; en: string }> = {
    "profile-count": { cs: `${value} scan profilů`, en: `${value} scan profiles` },
    "healthcare-profile": { cs: "healthcare referenční profil je dostupný", en: "healthcare reference profile is available" },
    "web-perimeter-profile": { cs: "web/API perimeter profil je dostupný", en: "web/API perimeter profile is available" },
    "enterprise-profile": { cs: "enterprise assurance profil je dostupný", en: "enterprise assurance profile is available" },
    "active-dast-guardrails": { cs: "aktivní DAST má fail-closed guardraily", en: "active DAST has fail-closed guardrails" },
    "queue-endpoint": { cs: "queue endpoint je dostupný", en: "queue endpoint is available" },
    "redis-configured": { cs: "Redis fronta je nakonfigurovaná", en: "Redis queue is configured" },
    "postgres-persistence": { cs: "PostgreSQL perzistence je aktivní", en: "PostgreSQL persistence is active" },
    "reports-path-configured": { cs: "evidence storage je nakonfigurovaný", en: "evidence storage is configured" },
    "progress-endpoint": { cs: "serverový progress endpoint je dostupný", en: "server-side progress endpoint is available" },
    "healthcare-check-count": { cs: `${value} healthcare kontrol v profilu`, en: `${value} healthcare checks in profile` },
    "healthcare-tool-catalog": { cs: `${value} healthcare nástrojů v katalogu`, en: `${value} healthcare tools in catalog` },
    "healthcare-tool-categories": { cs: `${value} kategorií scannerů`, en: `${value} scanner categories` },
    "greenbone-openscap-defectdojo": { cs: "Greenbone/OpenVAS, OpenSCAP a DefectDojo evidence jsou v pipeline", en: "Greenbone/OpenVAS, OpenSCAP, and DefectDojo evidence are in the pipeline" },
    "triage-api": { cs: "triage API je dostupné", en: "triage API is available" },
    "triage-owner-dates": { cs: "nálezy podporují vlastníka, poznámku a termíny", en: "findings support owner, note, and due dates" },
    "finding-audit-events": { cs: "audit události nálezů se persistují", en: "finding audit events are persisted" },
    "codex-remediation-export": { cs: "balík pro Codex je dostupný", en: "Codex remediation package is available" },
    "markdown-json-reports": { cs: "Markdown a JSON reporty", en: "Markdown and JSON reports" },
    "sarif-export": { cs: "SARIF export pro DefectDojo", en: "SARIF export for DefectDojo" },
    "pdf-pptx-export": { cs: "PDF/PPTX exporty", en: "PDF/PPTX exports" },
    "central-envelope": { cs: "centrální redigovaná obálka", en: "central redacted envelope" },
    "delivery-manifests": { cs: "delivery manifesty", en: "delivery manifests" },
    "akb-boundary-no-local-storage": { cs: "AKB prompty, odpovědi a chunky se lokálně neukládají", en: "AKB prompts, answers, and chunks are not stored locally" },
    "akb-requires-citations": { cs: "AKB odpovědi vyžadují citace", en: "AKB answers require citations" },
    "akb-rag-configured": { cs: "AKB RAG endpoint je nakonfigurovaný", en: "AKB RAG endpoint is configured" },
    "akb-auth-mode": { cs: `AKB auth režim: ${value}`, en: `AKB auth mode: ${value}` },
    "telemetry-ingest-endpoint": { cs: "centrální ingest endpoint je dostupný", en: "central ingest endpoint is available" },
    "telemetry-delivery-manifest": { cs: "telemetry delivery manifest se ukládá", en: "telemetry delivery manifest is stored" },
    "result-sink-enabled": { cs: `externí result sink: ${value}`, en: `external result sink: ${value}` },
    "defectdojo-export-configured": { cs: `DefectDojo export: ${value}`, en: `DefectDojo export: ${value}` },
    "project-registry-persistence": { cs: "registr projektů je perzistentní", en: "project registry is persistent" },
    "project-update-delete-api": { cs: "projekty lze upravovat a mazat přes API", en: "projects can be updated and deleted through API" },
    "project-path-validation": { cs: "cesty jsou validované pod povolenými rooty", en: "paths are validated under allowed roots" },
    "project-stack-detection": { cs: "detekce stacku je aktivní", en: "stack detection is active" },
    "project-autodiscovery": { cs: "automatické načítání /srv a /opt rootů je aktivní", en: "automatic /srv and /opt root discovery is active" },
    "project-roots-configured": { cs: "povolené project rooty jsou nakonfigurované", en: "allowed project roots are configured" },
    "auth-required": { cs: "API vyžaduje autentizaci", en: "API requires authentication" },
    "oidc-configured": { cs: "STRATOS OIDC/JWKS je nakonfigurovaný", en: "STRATOS OIDC/JWKS is configured" },
    "public-oidc-configured": { cs: "web má veřejnou OIDC konfiguraci", en: "web has public OIDC configuration" },
    "access-projection-configured": { cs: "centrální access projection je nakonfigurovaná", en: "central access projection is configured" },
    "scope-registry-configured": { cs: "centrální scope registry je nakonfigurovaný", en: "central scope registry is configured" },
    "policy-registry-configured": { cs: "centrální policy registry je nakonfigurovaný", en: "central policy registry is configured" },
    "policy-decision-configured": { cs: "centrální policy decision endpoint je nakonfigurovaný", en: "central policy decision endpoint is configured" },
    "policy-service-credential-configured": { cs: "runtime policy credential je nakonfigurovaný", en: "runtime policy credential is configured" },
    "tls-forwarded": { cs: "TLS terminace je předaná přes reverse proxy", en: "TLS termination is forwarded by reverse proxy" },
    "missing-healthcare-profile": { cs: "chybí healthcare referenční profil", en: "healthcare reference profile is missing" },
    "missing-web-perimeter-profile": { cs: "chybí web/API perimeter profil", en: "web/API perimeter profile is missing" },
    "missing-enterprise-profile": { cs: "chybí enterprise assurance profil", en: "enterprise assurance profile is missing" },
    "production-dast-unguarded": { cs: "některý profil dovoluje produkční aktivní DAST bez guardrailů", en: "a profile allows production active DAST without guardrails" },
    "missing-redis": { cs: "chybí Redis konfigurace", en: "Redis configuration is missing" },
    "missing-database": { cs: "chybí PostgreSQL perzistence", en: "PostgreSQL persistence is missing" },
    "missing-reports-path": { cs: "chybí REPORTS_PATH", en: "REPORTS_PATH is missing" },
    "missing-healthcare-check": { cs: `v healthcare profilu chybí kontrola ${value}`, en: `healthcare profile is missing ${value}` },
    "akb-rag-missing": { cs: "chybí SECURITY_PREFLIGHT_AKB_RAG_BASE_URL", en: "SECURITY_PREFLIGHT_AKB_RAG_BASE_URL is missing" },
    "akb-auth-missing": { cs: "AKB nemá caller bearer, OIDC client credentials ani service token", en: "AKB has no caller bearer, OIDC client credentials, or service token" },
    "telemetry-required-sink-missing": { cs: "povinný telemetry sink není nakonfigurovaný", en: "required telemetry sink is not configured" },
    "defectdojo-config-missing": { cs: "DefectDojo export je zapnutý, ale konfigurace není úplná", en: "DefectDojo export is enabled but not fully configured" },
    "project-autodiscovery-disabled": { cs: "automatické načítání projektů je vypnuté", en: "automatic project discovery is disabled" },
    "project-roots-missing": { cs: "chybí PROJECTS_ROOT_CONTAINER nebo PROJECTS_ROOTS_CONTAINER", en: "PROJECTS_ROOT_CONTAINER or PROJECTS_ROOTS_CONTAINER is missing" },
    "auth-not-required": { cs: "produkční API neběží ve vyžadovaném auth režimu", en: "production API is not running in required auth mode" },
    "oidc-not-configured": { cs: "OIDC/JWKS konfigurace není kompletní", en: "OIDC/JWKS configuration is incomplete" },
    "public-oidc-missing": { cs: "veřejná OIDC konfigurace webu není kompletní", en: "public web OIDC configuration is incomplete" },
    "access-projection-missing": { cs: "chybí centrální access projection endpoint", en: "central access projection endpoint is missing" },
    "scope-registry-missing": { cs: "chybí centrální scope registry", en: "central scope registry is missing" },
    "policy-registry-missing": { cs: "chybí centrální policy registry", en: "central policy registry is missing" },
    "policy-decision-missing": { cs: "chybí centrální policy decision endpoint", en: "central policy decision endpoint is missing" },
    "policy-service-credential-missing": { cs: "chybí runtime policy credential", en: "runtime policy credential is missing" }
  };

  return labels[signal.id]?.[locale] ?? (value ? `${signal.id}: ${value}` : signal.id);
}

function capabilitySignalValue(signal: CapabilityAuditSignal, locale: AppLocale): string {
  if (typeof signal.value === "boolean") {
    return signal.value ? translateStatus(locale, "configured") : translateStatus(locale, "not configured");
  }

  if (signal.value == null) return "";
  return String(signal.value);
}

function findingLocation(finding: ScanRunDetail["findings"][number], fallback: string): string {
  if (finding.filePath) return `${finding.filePath}${finding.line ? `:${finding.line}` : ""}`;
  if (finding.endpoint) return finding.endpoint;

  return fallback;
}

function findingScopeLabel(finding: ScanRunDetail["findings"][number], locale: AppLocale): string {
  return finding.scope === "platform" ? (locale === "cs" ? "Platforma" : "Platform") : locale === "cs" ? "Aplikace" : "Application";
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

function createInitialSettingsDraft(locale: AppLocale): SecuritySettingsDraft {
  return {
    displayName: uiText[locale].topbar.userName,
    email: "",
    role: uiText[locale].auth.localMode,
    language: locale,
    timezone: "Europe/Prague",
    theme: "auto",
    accent: "teal",
    highContrast: false,
    notifyTimezone: true,
    weekStart: "monday",
    timeFormat: "24h",
    dateFormat: "dd.mm.yyyy",
    compactMode: false,
    commandHints: true,
    flyoutToasts: true,
    markdown: true,
    keyboardShortcuts: true,
    defaultProfileId: "documentation-compliance",
    activeDastGuardrails: true,
    centralTelemetry: true,
    requireHealthDataProfile: true,
    twoFactor: false,
    password: ""
  };
}

function settingsCoreValuesFromDraft(draft: SecuritySettingsDraft): StratosSettingsCoreValues {
  return {
    displayName: draft.displayName,
    email: draft.email,
    role: draft.role,
    language: draft.language,
    timezone: draft.timezone,
    theme: draft.theme,
    accent: draft.accent,
    highContrast: draft.highContrast,
    notifyTimezone: draft.notifyTimezone,
    weekStart: draft.weekStart,
    timeFormat: draft.timeFormat,
    dateFormat: draft.dateFormat,
    compactMode: draft.compactMode,
    commandHints: draft.commandHints,
    flyoutToasts: draft.flyoutToasts,
    markdown: draft.markdown,
    keyboardShortcuts: draft.keyboardShortcuts,
    twoFactor: draft.twoFactor,
    password: draft.password
  };
}

export default function DashboardPage() {
  const [locale, setLocale] = useState<AppLocale>(defaultLocale);
  const [activeView, setActiveView] = useState<WorkspaceView>("new-scan");
  const [activeRailPanel, setActiveRailPanel] = useState<RailPanel>("security");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsMode, setSettingsMode] = useState<SettingsSurfaceMode>("modal");
  const [settingsActiveItemId, setSettingsActiveItemId] = useState("profile");
  const [savedSettingsDraft, setSavedSettingsDraft] = useState<SecuritySettingsDraft>(() => createInitialSettingsDraft(defaultLocale));
  const [settingsDraft, setSettingsDraft] = useState<SecuritySettingsDraft>(() => createInitialSettingsDraft(defaultLocale));
  const [profiles, setProfiles] = useState<ScanProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("documentation-compliance");
  const [doctor, setDoctor] = useState<ToolchainDoctor | null>(null);
  const [projects, setProjects] = useState<RegisteredProject[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [scanTargetMode, setScanTargetMode] = useState<ScanTargetMode>("project");
  const [webTargetUrl, setWebTargetUrl] = useState("");
  const [loadingProjects, setLoadingProjects] = useState(false);
  const [registeringProject, setRegisteringProject] = useState(false);
  const [projectMessage, setProjectMessage] = useState<string>(uiText[defaultLocale].projects.pathHelp);
  const [projectForm, setProjectForm] = useState<{
    name: string;
    path: string;
    owner: string;
    repositoryUrl: string;
    dataClassification: RegisteredProject["dataClassification"];
  }>({
    name: "SecurityPreflight",
    path: dockerProjectPath,
    owner: "",
    repositoryUrl: "",
    dataClassification: "internal"
  });
  const [scanRuns, setScanRuns] = useState<ScanRunSummary[]>([]);
  const [selectedRun, setSelectedRun] = useState<ScanRunDetail | null>(null);
  const [scanProgress, setScanProgress] = useState<ScanRunProgress | null>(null);
  const [loadingDoctor, setLoadingDoctor] = useState(false);
  const [loadingRuns, setLoadingRuns] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [commandOpen, setCommandOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState("");
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailMode, setDetailMode] = useState<DetailSurfaceMode>("sidebar");
  const [scanLogOpen, setScanLogOpen] = useState(false);
  const [scanLogMode, setScanLogMode] = useState<DetailSurfaceMode>("sidebar");
  const [projectRegistryOpen, setProjectRegistryOpen] = useState(false);
  const [exportingFormat, setExportingFormat] = useState<"PDF" | "PPTX" | null>(null);
  const [exportingCodex, setExportingCodex] = useState(false);
  const [triagingFindingId, setTriagingFindingId] = useState<string | null>(null);
  const [exportMessage, setExportMessage] = useState<string>(uiText[defaultLocale].messages.exportInitial);
  const [codexMessage, setCodexMessage] = useState<string>(uiText[defaultLocale].messages.codexInitial);
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null);
  const [authToken, setAuthToken] = useState<string | null>(null);
  const [authTokenInput, setAuthTokenInput] = useState("");
  const [authMessage, setAuthMessage] = useState<string>(uiText[defaultLocale].auth.initial);
  const [accessDenied, setAccessDenied] = useState(false);
  const accessDeniedRef = useRef(false);
  const [oidcClient, setOidcClient] = useState<OidcClientConfig | null>(null);
  const [akbStatus, setAkbStatus] = useState<AkbStatus | null>(null);
  const [akbQuestion, setAkbQuestion] = useState<string>(uiText[defaultLocale].telemetry.auditPromptText);
  const [akbAnswer, setAkbAnswer] = useState<AkbAnswer | null>(null);
  const [akbLoading, setAkbLoading] = useState(false);
  const [akbMessage, setAkbMessage] = useState<string>(uiText[defaultLocale].messages.akbInitial);
  const [capabilityAudit, setCapabilityAudit] = useState<CapabilityAudit | null>(null);
  const [scanResult, setScanResult] = useState<ScanActionResult>({
    mode: "plan",
    status: "idle",
    message: uiText[defaultLocale].messages.scanReady
  });
  const copy = uiText[locale];
  const fallbackTools = localizedFallbackTools[locale];
  const baseCapabilityRows = localizedCapabilityRows[locale];
  const capabilityRows = useMemo(
    () => mergeCapabilityAuditRows(baseCapabilityRows, capabilityAudit, locale),
    [baseCapabilityRows, capabilityAudit, locale]
  );
  const executionStages = localizedExecutionStages[locale];
  const selectedProject = projects.find((project) => project.id === selectedProjectId) ?? projects[0] ?? null;
  const selectedProjectPolicy = projectPolicyDetails(selectedProject?.policyBinding);
  const effectiveProfileId = selectedProfileId;
  const activeScanProject = selectedProject ?? {
    id: "security-preflight-local",
    name: "SecurityPreflight",
    path: dockerProjectPath,
    dataClassification: effectiveProfileId === "healthcare-reference" ? "health-data" : "internal"
  };

  const selectedProfile = useMemo(
    () => profiles.find((profile) => profile.id === effectiveProfileId),
    [effectiveProfileId, profiles]
  );
  const queueRequiresWebTarget = scanTargetMode === "project" && selectedProfile?.allowActiveDast === true;
  const selectedProjectPublicUrl = selectedProject?.publicUrl ?? "";
  const selectedProfileDescription = selectedProfile
    ? profileDescription(locale, selectedProfile.id, selectedProfile.description)
    : copy.messages.loadProfilesFallback;
  const profileOptions = useMemo(
    () => (scanTargetMode === "web" ? profiles.filter((profile) => profile.allowActiveDast) : profiles),
    [profiles, scanTargetMode]
  );
  const projectRows = useMemo<ProjectRow[]>(
    () =>
      projects.map((project) => ({
        id: project.id,
        name: project.name,
        path: project.path,
        stack: project.technologyStack.length ? project.technologyStack.join(" / ") : copy.projects.stackUnknown,
        data: copy.projects.classifications[project.dataClassification],
        dataClassification: project.dataClassification,
        owner: project.owner ?? "-",
        updatedAt: formatDateTime(project.updatedAt, locale)
      })),
    [copy.projects, locale, projects]
  );
  const projectPickerProjects = useMemo<ProjectPickerProject[]>(
    () =>
      projects.map((project) => ({
        id: project.id,
        name: project.name,
        code: project.owner ?? null,
        detail: project.path,
        group: copy.projects.classifications[project.dataClassification],
        initials: project.name
          .split(/[\s/-]+/)
          .filter(Boolean)
          .slice(0, 2)
          .map((part) => part[0]?.toUpperCase())
          .join(""),
        status: project.publicUrl ? copy.projects.publicUrl : copy.runPanel.directoryTarget,
        tone: project.dataClassification === "health-data" ? "danger" : project.dataClassification === "sensitive" ? "warning" : "neutral"
      })),
    [copy.projects, copy.runPanel.directoryTarget, projects]
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
        version: tool.version ?? tool.message ?? copy.dashboard.toolVersionFallback
      }))
    : fallbackTools;
  const scanRows = useMemo<ScanRow[]>(
    () =>
      scanRuns.map((run) => ({
        id: run.id,
        project: run.project.name,
        profile: profileName(locale, run.profile.id, run.profile.name),
        status: run.status,
        result: gateLabel(run.gateResult),
        findings: copy.execution.findingsCount(run.findingCount),
        finished: formatDateTime(run.finishedAt ?? run.startedAt, locale)
      })),
    [copy.execution, locale, scanRuns]
  );
  const latestRun = selectedRun ?? scanRuns[0] ?? null;
  const reportArtifactTotal = 5;
  const reportArtifactCount = latestRun
    ? [
        latestRun.evidence.hasMarkdownReport,
        latestRun.evidence.hasJsonReport,
        latestRun.evidence.hasSarifReport,
        latestRun.evidence.hasCentralEnvelope,
        latestRun.evidence.hasCentralTelemetryDelivery || latestRun.evidence.hasDefectDojoDelivery
      ].filter(Boolean).length
    : 0;
  const filteredCapabilityRows = useMemo(() => {
    const query = searchQuery.trim().toLowerCase();
    if (!query) return capabilityRows;

    return capabilityRows.filter((row) =>
      `${row.area} ${row.status} ${row.implemented} ${row.gap} ${row.priority}`.toLowerCase().includes(query)
    );
  }, [capabilityRows, searchQuery]);
  const maturityScore = Math.round(
    (capabilityRows.filter((row) => row.status === "Ready").length * 100 +
      capabilityRows.filter((row) => row.status === "Partial").length * 55) /
      capabilityRows.length
  );
  const criticalCapabilityRows = capabilityRows.filter((row) => row.priority === "P0" && row.status !== "Ready");
  const criticalGaps = criticalCapabilityRows.length;
  const scanGate = scanResult.status === "error" || scanResult.blocked ? "Blocked" : scanResult.status === "success" ? "Ready" : "Partial";
  const authReady = authStatus ? !accessDenied && (!authStatus.required || Boolean(authToken)) : false;
  const authLabel = accessDenied
    ? copy.auth.accessDenied
    : authStatus?.required
      ? authToken
        ? copy.auth.authenticated
        : copy.auth.required
      : copy.auth.localMode;
  const settingsDirty = JSON.stringify(savedSettingsDraft) !== JSON.stringify(settingsDraft);
  const settingsValues = useMemo(() => settingsCoreValuesFromDraft(settingsDraft), [settingsDraft]);
  const settingsProfileOptions = useMemo(
    () =>
      profiles.length
        ? profiles.map((profile) => ({
            id: profile.id,
            label: profileName(locale, profile.id, profile.name),
            description: profileDescription(locale, profile.id, profile.description)
          }))
        : [
            {
              id: settingsDraft.defaultProfileId,
              label: profileName(locale, settingsDraft.defaultProfileId, settingsDraft.defaultProfileId),
              description: copy.settings.profileFallback
            }
          ],
    [copy.settings.profileFallback, locale, profiles, settingsDraft.defaultProfileId]
  );
  const settingsThemeOptions = useMemo(
    () => [
      { id: "auto", label: copy.settings.themeAuto, preview: <span className="stratos-settings-preview-tile is-auto" /> },
      { id: "light", label: copy.settings.themeLight, preview: <span className="stratos-settings-preview-tile" /> },
      { id: "dark", label: copy.settings.themeDark, preview: <span className="stratos-settings-preview-tile is-dark" /> }
    ],
    [copy.settings.themeAuto, copy.settings.themeDark, copy.settings.themeLight]
  );
  const settingsAccentOptions = useMemo(
    () => [
      { id: "slate", label: "Slate", color: "#5f6673" },
      { id: "teal", label: "Teal", color: "#12a39a" },
      { id: "blue", label: "Blue", color: "#1d9bf0" },
      { id: "green", label: "Green", color: "#3fbf83" },
      { id: "rose", label: "Rose", color: "#ec4f8c" },
      { id: "orange", label: "Orange", color: "#e56b13" }
    ],
    []
  );
  const settingsAppNavItems = useMemo<SettingsNavItem[]>(
    () => [
      {
        id: "scan-defaults",
        label: copy.settings.scanDefaults,
        description: copy.settings.scanDefaultsDescription,
        group: copy.settings.applicationGroup,
        icon: <Gauge size={16} aria-hidden="true" />,
        keywords: ["scan", "profile", "default", "kontrola", "profil"]
      },
      {
        id: "security-guardrails",
        label: copy.settings.securityGuardrails,
        description: copy.settings.securityGuardrailsDescription,
        group: copy.settings.applicationGroup,
        icon: <ShieldCheck size={16} aria-hidden="true" />,
        keywords: ["security", "guardrail", "telemetry", "dast", "healthcare", "zdravotni"]
      }
    ],
    [copy.settings]
  );
  const settingsAppSections = useMemo<SettingsContentSection[]>(
    () => [
      {
        id: "scan-defaults-main",
        navItemId: "scan-defaults",
        title: copy.settings.scanDefaults,
        description: copy.settings.scanDefaultsDescription,
        keywords: ["profile", "scan", "default", "web"],
        children: (
          <>
            <SettingsField label={copy.settings.defaultProfile} description={copy.settings.defaultProfileHelp}>
              <SettingsChoiceGroup
                value={settingsDraft.defaultProfileId}
                columns={1}
                options={settingsProfileOptions}
                onChange={(defaultProfileId) => {
                  setSettingsDraft((current) => ({ ...current, defaultProfileId }));
                  if (profiles.some((profile) => profile.id === defaultProfileId)) {
                    setSelectedProfileId(defaultProfileId);
                  }
                }}
              />
            </SettingsField>
            <SettingsField label={copy.settings.workspaceRoot} description={copy.settings.workspaceRootHelp}>
              <SettingsTextInput icon={<FolderGit2 size={15} aria-hidden="true" />} value={dockerProjectPath} readOnly onChange={() => undefined} />
            </SettingsField>
          </>
        )
      },
      {
        id: "security-guardrails-main",
        navItemId: "security-guardrails",
        title: copy.settings.securityGuardrails,
        description: copy.settings.securityGuardrailsDescription,
        keywords: ["guardrail", "telemetry", "dast", "healthcare"],
        children: (
          <>
            <SettingsToggle
              label={copy.settings.activeDastGuardrails}
              description={copy.settings.activeDastGuardrailsHelp}
              checked={settingsDraft.activeDastGuardrails}
              onChange={(activeDastGuardrails) => setSettingsDraft((current) => ({ ...current, activeDastGuardrails }))}
            />
            <SettingsToggle
              label={copy.settings.centralTelemetry}
              description={copy.settings.centralTelemetryHelp}
              checked={settingsDraft.centralTelemetry}
              onChange={(centralTelemetry) => setSettingsDraft((current) => ({ ...current, centralTelemetry }))}
            />
            <SettingsToggle
              label={copy.settings.requireHealthDataProfile}
              description={copy.settings.requireHealthDataProfileHelp}
              checked={settingsDraft.requireHealthDataProfile}
              onChange={(requireHealthDataProfile) => setSettingsDraft((current) => ({ ...current, requireHealthDataProfile }))}
            />
          </>
        )
      }
    ],
    [copy.settings, profiles, settingsDraft.activeDastGuardrails, settingsDraft.centralTelemetry, settingsDraft.defaultProfileId, settingsDraft.requireHealthDataProfile, settingsProfileOptions]
  );

  useEffect(() => {
    const localizedDefaultNames: string[] = [uiText.cs.topbar.userName, uiText.en.topbar.userName];
    const syncLocalizedIdentity = (current: SecuritySettingsDraft): SecuritySettingsDraft => {
      const nextDisplayName = localizedDefaultNames.includes(current.displayName) ? copy.topbar.userName : current.displayName;
      if (current.displayName === nextDisplayName && current.role === authLabel && current.language === locale) {
        return current;
      }

      return { ...current, displayName: nextDisplayName, role: authLabel, language: locale };
    };

    setSettingsDraft(syncLocalizedIdentity);
    setSavedSettingsDraft(syncLocalizedIdentity);
  }, [authLabel, copy.topbar.userName, locale]);

  const selectWorkspaceView = useCallback((view: WorkspaceView) => {
    setActiveView(view);
    setActiveRailPanel(railPanelByWorkspaceView[view]);
    setSidebarOpen(true);
  }, []);

  const handleRailItemSelect = useCallback(
    (itemId: string) => {
      if (itemId === "settings") {
        setSettingsOpen(true);
        return;
      }

      const nextPanel: RailPanel = itemId === "evidence" ? "evidence" : "security";

      if (nextPanel === activeRailPanel) {
        setSidebarOpen((current) => !current);
        return;
      }

      setActiveRailPanel(nextPanel);
      setActiveView(defaultViewByRailPanel[nextPanel]);
      setSidebarOpen(true);
    },
    [activeRailPanel]
  );

  const commandItems = useMemo<CommandCenterItem[]>(
    () => [
      {
        id: "view-new-scan",
        type: "action",
        title: copy.views.newScan,
        subtitle: scanTargetMode === "web" ? webTargetUrl.trim() || copy.runPanel.webTargetPlaceholder : activeScanProject.path,
        icon: <Play size={18} />,
        tone: "green",
        primaryAction: {
          id: "open",
          label: copy.command.open,
          onSelect: () => selectWorkspaceView("new-scan")
        }
      },
      {
        id: "view-dashboard",
        type: "dashboard",
        title: copy.views.dashboard,
        subtitle: copy.command.dashboardSubtitle,
        icon: <LayoutDashboard size={18} />,
        primaryAction: {
          id: "open",
          label: copy.command.open,
          onSelect: () => selectWorkspaceView("dashboard")
        }
      },
      {
        id: "view-capabilities",
        type: "dashboard",
        title: copy.views.capabilities,
        subtitle: copy.command.p0Gaps(criticalGaps),
        icon: <Gauge size={18} />,
        tone: criticalGaps ? "amber" : "green",
        primaryAction: {
          id: "open",
          label: copy.command.open,
          onSelect: () => selectWorkspaceView("capabilities")
        }
      },
      {
        id: "view-execution",
        type: "report",
        title: copy.views.execution,
        subtitle: latestRun ? latestRun.id : copy.command.noEvidenceLoaded,
        icon: <Archive size={18} />,
        primaryAction: {
          id: "open",
          label: copy.command.open,
          onSelect: () => selectWorkspaceView("execution")
        }
      },
      {
        id: "view-telemetry",
        type: "report",
        title: copy.views.telemetry,
        subtitle: akbStatus?.configured ? copy.command.akbConfigured : copy.command.akbNotConfigured,
        icon: <Database size={18} />,
        tone: akbStatus?.configured ? "green" : "amber",
        primaryAction: {
          id: "open",
          label: copy.command.open,
          onSelect: () => selectWorkspaceView("telemetry")
        }
      },
      {
        id: "action-run-scan",
        type: "action",
        title: copy.command.runScan,
        subtitle: effectiveProfileId,
        icon: <Play size={18} />,
        tone: "green",
        primaryAction: {
          id: "run",
          label: copy.command.queue,
          disabled: !authReady || queueRequiresWebTarget,
          onSelect: () => void runScan("queue")
        }
      },
      {
        id: "action-dry-run",
        type: "action",
        title: copy.command.dryRunPlan,
        subtitle: effectiveProfileId,
        icon: <ClipboardList size={18} />,
        primaryAction: {
          id: "plan",
          label: copy.command.plan,
          disabled: !authReady,
          onSelect: () => void runScan("plan")
        }
      },
      {
        id: "action-export-pdf",
        type: "report",
        title: copy.command.exportPdf,
        subtitle: latestRun?.id ?? copy.command.noLatestRun,
        icon: <FileText size={18} />,
        tone: latestRun ? "blue" : "amber",
        primaryAction: {
          id: "export",
          label: copy.command.export,
          disabled: !latestRun || !authReady,
          onSelect: () => void exportLatestRun("PDF")
        }
      },
      {
        id: "action-export-pptx",
        type: "report",
        title: copy.command.exportPptx,
        subtitle: latestRun?.id ?? copy.command.noLatestRun,
        icon: <Presentation size={18} />,
        tone: latestRun ? "purple" : "amber",
        primaryAction: {
          id: "export",
          label: copy.command.export,
          disabled: !latestRun || !authReady,
          onSelect: () => void exportLatestRun("PPTX")
        }
      },
      {
        id: "action-export-codex",
        type: "report",
        title: copy.command.exportCodex,
        subtitle: latestRun?.id ?? copy.command.noLatestRun,
        icon: <Sparkles size={18} />,
        tone: latestRun ? "blue" : "amber",
        primaryAction: {
          id: "export",
          label: copy.command.export,
          disabled: !latestRun || !authReady,
          onSelect: () => void exportCodexRemediation()
        }
      }
    ],
    [
      activeScanProject.path,
      akbStatus?.configured,
      authReady,
      copy.command,
      copy.runPanel.webTargetPlaceholder,
      copy.views,
      criticalGaps,
      effectiveProfileId,
      latestRun,
      queueRequiresWebTarget,
      scanTargetMode,
      selectWorkspaceView,
      webTargetUrl
    ]
  );

  const projectColumns = useMemo<Array<DataTableColumn<ProjectRow>>>(
    () => [
      {
        id: "project",
        label: copy.columns.project,
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
        label: copy.columns.stack,
        width: "minmax(170px, 1fr)",
        render: (row) => <span className="security-wrap">{row.stack}</span>
      },
      {
        id: "data",
        label: copy.columns.data,
        width: 132,
        render: (row) => <Badge tone={row.dataClassification === "health-data" || row.dataClassification === "sensitive" ? "danger" : "neutral"}>{row.data}</Badge>
      },
      {
        id: "owner",
        label: copy.columns.owner,
        width: "minmax(130px, 0.8fr)",
        render: (row) => row.owner
      },
      {
        id: "updated",
        label: copy.columns.updated,
        width: "minmax(170px, 1fr)",
        render: (row) => row.updatedAt
      }
    ],
    [copy.columns, locale]
  );

  const scanColumns = useMemo<Array<DataTableColumn<ScanRow>>>(
    () => [
      {
        id: "project",
        label: copy.columns.project,
        width: "minmax(170px, 1fr)",
        sortable: true,
        sortAccessor: (row) => row.project,
        render: (row) => row.project
      },
      {
        id: "profile",
        label: copy.columns.profile,
        width: "minmax(220px, 1.2fr)",
        render: (row) => <code>{row.profile}</code>
      },
      {
        id: "status",
        label: copy.columns.status,
        width: 110,
        render: (row) => <Badge tone={statusTone(row.status)}>{statusDisplayLabel(row.status, locale)}</Badge>
      },
      {
        id: "result",
        label: copy.columns.result,
        width: 120,
        render: (row) => <RagBadge status={statusRag(row.result)} label={gateDisplayLabel(row.result, locale)} />
      },
      {
        id: "findings",
        label: copy.columns.findings,
        width: 120,
        render: (row) => row.findings
      },
      {
        id: "finished",
        label: copy.columns.finished,
        width: "minmax(170px, 1fr)",
        render: (row) => row.finished
      }
    ],
    [copy.columns, locale]
  );

  const capabilityColumns = useMemo<Array<DataTableColumn<CapabilityRow>>>(
    () => [
      {
        id: "area",
        label: copy.columns.capability,
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
        label: copy.columns.status,
        width: 120,
        sortable: true,
        sortAccessor: (row) => row.status,
        render: (row) => <RagBadge status={statusRag(row.status)} label={statusDisplayLabel(row.status, locale)} />
      },
      {
        id: "implemented",
        label: copy.columns.implemented,
        width: "minmax(280px, 1.4fr)",
        render: (row) => <span className="security-wrap">{row.implemented}</span>
      },
      {
        id: "gap",
        label: copy.columns.gap,
        width: "minmax(320px, 1.6fr)",
        render: (row) => <span className="security-wrap">{row.gap}</span>
      }
    ],
    [copy.columns, locale]
  );

  const navGroups = useMemo<WorkspaceNavGroup[]>(
    () => [
      {
        id: "security",
        label: copy.views.security,
        items: [
          {
            id: "new-scan",
            label: copy.views.newScan,
            icon: <Play size={16} />,
            active: activeView === "new-scan"
          },
          {
            id: "dashboard",
            label: copy.views.dashboard,
            icon: <LayoutDashboard size={16} />,
            active: activeView === "dashboard"
          },
          {
            id: "capabilities",
            label: copy.views.capabilities,
            icon: <Gauge size={16} />,
            badge: criticalGaps,
            active: activeView === "capabilities"
          }
        ]
      },
      {
        id: "evidence",
        label: copy.views.evidence,
        items: [
          {
            id: "execution",
            label: copy.views.executionShort,
            icon: <Activity size={16} />,
            active: activeView === "execution"
          },
          {
            id: "telemetry",
            label: copy.views.telemetryShort,
            icon: <Database size={16} />,
            active: activeView === "telemetry"
          },
          {
            id: "findings",
            label: copy.views.findings,
            icon: <FileWarning size={16} />,
            disabled: true,
            disabledReason: copy.disabledReasons.findings
          }
        ]
      }
    ],
    [activeView, copy.disabledReasons.findings, copy.views, criticalGaps]
  );

  useEffect(() => {
    const storedLocale = window.localStorage.getItem(localeStorageKey);
    if (storedLocale === "cs" || storedLocale === "en") {
      setLocale(storedLocale);
    }
  }, []);

  useEffect(() => {
    document.documentElement.lang = locale;

    const exportDefaults: string[] = [uiText.cs.messages.exportInitial, uiText.en.messages.exportInitial];
    const codexDefaults: string[] = [uiText.cs.messages.codexInitial, uiText.en.messages.codexInitial];
    const authDefaults: string[] = [uiText.cs.auth.initial, uiText.en.auth.initial];
    const akbDefaults: string[] = [uiText.cs.messages.akbInitial, uiText.en.messages.akbInitial];
    const scanDefaults: string[] = [uiText.cs.messages.scanReady, uiText.en.messages.scanReady];
    const auditPrompts: string[] = [uiText.cs.telemetry.auditPromptText, uiText.en.telemetry.auditPromptText];
    const projectDefaults: string[] = [uiText.cs.projects.pathHelp, uiText.en.projects.pathHelp];

    setExportMessage((current) => (exportDefaults.includes(current) ? copy.messages.exportInitial : current));
    setCodexMessage((current) => (codexDefaults.includes(current) ? copy.messages.codexInitial : current));
    setAuthMessage((current) => (authDefaults.includes(current) ? copy.auth.initial : current));
    setAkbMessage((current) => (akbDefaults.includes(current) ? copy.messages.akbInitial : current));
    setAkbQuestion((current) => (auditPrompts.includes(current) ? copy.telemetry.auditPromptText : current));
    setProjectMessage((current) => (projectDefaults.includes(current) ? copy.projects.pathHelp : current));
    setScanResult((current) =>
      scanDefaults.includes(current.message) ? { ...current, message: copy.messages.scanReady } : current
    );
  }, [copy, locale]);

  useEffect(() => {
    if (!authStatus) return;

    const authStatusMessages: string[] = [
      uiText.cs.auth.initial,
      uiText.en.auth.initial,
      uiText.cs.auth.apiRequired,
      uiText.en.auth.apiRequired,
      uiText.cs.auth.apiRequiredIncomplete,
      uiText.en.auth.apiRequiredIncomplete,
      uiText.cs.auth.localNoAuth,
      uiText.en.auth.localNoAuth
    ];

    setAuthMessage((current) => {
      if (!authStatusMessages.includes(current)) return current;

      return authStatus.required
        ? authStatus.configured
          ? copy.auth.apiRequired
          : copy.auth.apiRequiredIncomplete
        : copy.auth.localNoAuth;
    });
  }, [authStatus, copy.auth]);

  function changeLocale(nextLocale: AppLocale) {
    window.localStorage.setItem(localeStorageKey, nextLocale);
    setLocale(nextLocale);
  }

  function handleSettingsCoreValueChange(key: StratosSettingsCoreValueKey, value: StratosSettingsCoreValue) {
    if (key === "language" && (value === "cs" || value === "en")) {
      changeLocale(value);
    }

    setSettingsDraft((current) => {
      switch (key) {
        case "displayName":
          return { ...current, displayName: String(value) };
        case "email":
          return { ...current, email: String(value) };
        case "role":
          return { ...current, role: String(value) };
        case "password":
          return { ...current, password: String(value) };
        case "twoFactor":
          return { ...current, twoFactor: Boolean(value) };
        case "theme":
          return { ...current, theme: String(value) as SecuritySettingsTheme };
        case "accent":
          return { ...current, accent: String(value) };
        case "highContrast":
          return { ...current, highContrast: Boolean(value) };
        case "language":
          return value === "cs" || value === "en" ? { ...current, language: value } : current;
        case "timezone":
          return { ...current, timezone: String(value) };
        case "notifyTimezone":
          return { ...current, notifyTimezone: Boolean(value) };
        case "weekStart":
          return { ...current, weekStart: String(value) as SecuritySettingsDraft["weekStart"] };
        case "timeFormat":
          return { ...current, timeFormat: String(value) as SecuritySettingsDraft["timeFormat"] };
        case "dateFormat":
          return { ...current, dateFormat: String(value) as SecuritySettingsDraft["dateFormat"] };
        case "compactMode":
          return { ...current, compactMode: Boolean(value) };
        case "commandHints":
          return { ...current, commandHints: Boolean(value) };
        case "flyoutToasts":
          return { ...current, flyoutToasts: Boolean(value) };
        case "markdown":
          return { ...current, markdown: Boolean(value) };
        case "keyboardShortcuts":
          return { ...current, keyboardShortcuts: Boolean(value) };
        default:
          return current;
      }
    });
  }

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
            window.sessionStorage.removeItem(oidcAutoLoginStartedKey);
            window.sessionStorage.removeItem(oidcSkipAutoLoginKey);
            persistAuthToken(completedToken);
            setAuthMessage(copy.auth.oidcEstablished);
          }
        }
      } catch (error) {
        setAuthMessage(userFacingErrorMessage(error, copy.auth.oidcFailed));
      } finally {
        await refreshAuthStatus();
      }
    }

    void initializeAuth();
  }, []);

  useEffect(() => {
    if (!authStatus || authToken || !oidcClient || accessDenied) return;
    if (authStatus.mode !== "oidc" || !authStatus.required || !authStatus.configured) return;
    if (new URLSearchParams(window.location.search).has("code")) return;
    if (window.sessionStorage.getItem(oidcSkipAutoLoginKey) === "true") return;

    window.sessionStorage.setItem(oidcAutoLoginStartedKey, `${oidcClient.issuer}|${oidcClient.clientId}|${oidcClient.redirectUri}`);
    setAuthMessage(copy.auth.oidcStarting);
    void startOidcLogin(oidcClient).catch((error) => {
      window.sessionStorage.removeItem(oidcAutoLoginStartedKey);
      setAuthMessage(userFacingErrorMessage(error, copy.auth.oidcFailed));
    });
  }, [accessDenied, authStatus, authToken, oidcClient, copy.auth]);

  useEffect(() => {
    let active = true;

    async function loadProfiles() {
      try {
        if (!authStatus) return;
        if (accessDenied) return;
        if (!authReady && authStatus.required) return;

        const payload = await fetchJson<{ data: ScanProfile[] }>(`${apiBaseUrl}/api/v1/scan-profiles`, undefined, authToken);

        if (!active || accessDeniedRef.current) return;

        setProfiles(payload.data);
        if (!payload.data.some((profile) => profile.id === selectedProfileId)) {
          setSelectedProfileId(payload.data[0]?.id ?? "documentation-compliance");
        }
      } catch (error) {
        if (!active) return;
        if (handleApiAccessFailure(error)) return;

        setScanResult({
          mode: "plan",
          status: "error",
          message: userFacingErrorMessage(error, copy.messages.loadProfilesFailed)
        });
      }
    }

    void loadProfiles();

    return () => {
      active = false;
    };
  }, [accessDenied, authReady, authStatus?.required, authToken, selectedProfileId]);

  useEffect(() => {
    if (authReady) {
      void refreshProjects();
    }
  }, [authReady, authToken]);

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
    if (authReady) {
      void refreshCapabilityAudit();
    }
  }, [authReady, authToken]);

  useEffect(() => {
    if (!selectedProfile?.allowActiveDast || scanTargetMode === "web") {
      return;
    }

    setScanTargetMode("web");
    if (selectedProjectPublicUrl && !webTargetUrl.trim()) {
      setWebTargetUrl(selectedProjectPublicUrl);
    }
    setScanResult((current) => ({
      ...current,
      mode: "plan",
      status: "success",
      message: selectedProjectPublicUrl ? copy.messages.activeProfileSwitchedToSavedWebTarget : copy.messages.activeProfileSwitchedToWebTarget,
      blocked: !selectedProjectPublicUrl,
      blockedReasons: selectedProjectPublicUrl ? [] : [copy.messages.activeProfileNeedsWebTargetReason],
      gate: selectedProjectPublicUrl ? "ready" : "blocked",
      stepCount: selectedProfile.checks.length
    }));
  }, [copy.messages, scanTargetMode, selectedProfile, selectedProjectPublicUrl, webTargetUrl]);

  useEffect(() => {
    if (scanTargetMode !== "web" || webTargetUrl.trim()) {
      return;
    }

    if (selectedProjectPublicUrl) {
      setWebTargetUrl(selectedProjectPublicUrl);
    }
  }, [scanTargetMode, selectedProjectPublicUrl, webTargetUrl]);

  useEffect(() => {
    if (scanTargetMode !== "web" || !selectedProfile?.allowActiveDast || !hostFromUrl(webTargetUrl.trim())) {
      return;
    }

    setScanResult((current) => {
      if (!current.blocked || !current.blockedReasons?.includes(copy.messages.activeProfileNeedsWebTargetReason)) {
        return current;
      }

      return {
        ...current,
        status: "success",
        message: copy.messages.planReady,
        blocked: false,
        blockedReasons: [],
        gate: "ready",
        stepCount: selectedProfile.checks.length
      };
    });
  }, [copy.messages, scanTargetMode, selectedProfile, webTargetUrl]);

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

  async function refreshProjects() {
    if (!authReady) {
      setProjectMessage(copy.projects.authRequired);
      return;
    }

    setLoadingProjects(true);

    try {
      const payload = await fetchJson<{ data: RegisteredProject[] }>(`${apiBaseUrl}/api/v1/projects`, undefined, authToken);
      if (accessDeniedRef.current) return;
      setProjects(payload.data);

      if (payload.data.length && !payload.data.some((project) => project.id === selectedProjectId)) {
        setSelectedProjectId(payload.data[0]?.id ?? "");
      }

      if (!payload.data.length) {
        setSelectedProjectId("");
      }
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setProjectMessage(userFacingErrorMessage(error, copy.projects.loadFailed));
    } finally {
      setLoadingProjects(false);
    }
  }

  async function registerProject() {
    if (!authReady) {
      setProjectMessage(copy.projects.authRequired);
      return;
    }

    const name = projectForm.name.trim();
    const projectPath = projectForm.path.trim();

    if (!name || !projectPath) {
      setProjectMessage(copy.projects.pathHelp);
      return;
    }

    setRegisteringProject(true);

    try {
      const payload = await fetchJson<{ data: RegisteredProject }>(`${apiBaseUrl}/api/v1/projects`, {
        method: "POST",
        body: JSON.stringify({
          name,
          path: projectPath,
          owner: projectForm.owner.trim() || null,
          repositoryUrl: projectForm.repositoryUrl.trim() || null,
          dataClassification: projectForm.dataClassification
        })
      }, authToken);

      if (accessDeniedRef.current) return;
      setProjects((current) => [...current.filter((project) => project.id !== payload.data.id), payload.data]);
      setSelectedProjectId(payload.data.id);
      setProjectMessage(copy.projects.projectRegistered(payload.data.name));
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setProjectMessage(userFacingErrorMessage(error, copy.projects.registrationFailed));
    } finally {
      setRegisteringProject(false);
    }
  }

  async function refreshAuthStatus() {
    try {
      const payload = await fetchJson<{ data: AuthStatus }>(`${apiBaseUrl}/api/v1/auth/status`);
      setAuthStatus(payload.data);
      setAuthMessage(
        payload.data.required
          ? payload.data.configured
            ? copy.auth.apiRequired
            : copy.auth.apiRequiredIncomplete
          : copy.auth.localNoAuth
      );
    } catch (error) {
      setAuthStatus(null);
      setAuthMessage(userFacingErrorMessage(error, copy.auth.statusUnavailable));
    }
  }

  function setAccessDeniedMode(nextAccessDenied: boolean) {
    accessDeniedRef.current = nextAccessDenied;
    setAccessDenied(nextAccessDenied);
  }

  function persistAuthToken(token: string) {
    const trimmed = token.trim();
    if (!trimmed) return;

    window.localStorage.setItem(authTokenStorageKey, trimmed);
    window.sessionStorage.removeItem(oidcAutoLoginStartedKey);
    window.sessionStorage.removeItem(oidcSkipAutoLoginKey);
    setAccessDeniedMode(false);
    setAuthToken(trimmed);
    setAuthTokenInput("");
  }

  function clearWorkspaceData() {
    setProfiles([]);
    setProjects([]);
    setScanRuns([]);
    setSelectedRun(null);
    setScanProgress(null);
    setDoctor(null);
    setAkbStatus(null);
    setAkbAnswer(null);
    setCapabilityAudit(null);
    setDetailOpen(false);
    setScanLogOpen(false);
    setCommandOpen(false);
    setLoadingProjects(false);
    setLoadingRuns(false);
    setLoadingDoctor(false);
    setRegisteringProject(false);
    setExportingFormat(null);
    setTriagingFindingId(null);
    setAkbLoading(false);
  }

  function clearAuthToken() {
    window.localStorage.removeItem(authTokenStorageKey);
    setAccessDeniedMode(false);
    setAuthToken(null);
    setAuthTokenInput("");
    setAuthMessage(copy.auth.tokenCleared);
    clearWorkspaceData();
  }

  function handleApiAuthFailure(error: unknown) {
    if (!isAuthenticationFailure(error)) return false;

    clearAuthToken();
    setAuthMessage(copy.auth.sessionExpired);
    return true;
  }

  function activateAccessDenied(error: unknown) {
    clearWorkspaceData();
    setAccessDeniedMode(true);
    setAuthMessage(userFacingErrorMessage(error, copy.auth.accessDeniedBody));
    setProjectMessage(copy.auth.accessDeniedBody);
    setExportMessage(copy.auth.accessDeniedBody);
    setAkbMessage(copy.auth.accessDeniedBody);
    setScanResult({ mode: "plan", status: "error", message: copy.auth.accessDeniedBody });
  }

  function handleApiAuthorizationFailure(error: unknown) {
    if (!isAuthorizationFailure(error)) return false;

    activateAccessDenied(error);
    return true;
  }

  function handleApiAccessFailure(error: unknown) {
    if (handleApiAuthFailure(error)) return true;
    if (handleApiAuthorizationFailure(error)) return true;
    return false;
  }

  async function signInWithOidc() {
    if (!oidcClient) {
      setAuthMessage(copy.auth.oidcNotConfigured);
      return;
    }

    setAccessDeniedMode(false);
    window.sessionStorage.removeItem(oidcSkipAutoLoginKey);
    window.sessionStorage.removeItem(oidcAutoLoginStartedKey);
    await startOidcLogin(oidcClient);
  }

  function signOut() {
    const logoutUrl = oidcClient ? oidcLogoutUrl(oidcClient) : null;
    window.sessionStorage.setItem(oidcSkipAutoLoginKey, "true");
    window.sessionStorage.removeItem(oidcAutoLoginStartedKey);
    clearAuthToken();

    if (logoutUrl && authStatus?.mode === "oidc") {
      window.location.assign(logoutUrl);
    }
  }

  async function loadScanRunProgress(scanRunId: string): Promise<ScanRunProgress | null> {
    const payload = await fetchOptionalJson<{ data: ScanRunProgress }>(`${apiBaseUrl}/api/v1/scans/runs/${scanRunId}/progress`, undefined, authToken);

    if (!payload) {
      return null;
    }

    if (accessDeniedRef.current) return null;
    setScanProgress(payload.data);
    return payload.data;
  }

  async function loadScanRunDetail(scanRunId: string, options: { refreshProgress?: boolean } = {}): Promise<ScanRunDetail | null> {
    const refreshProgress = options.refreshProgress ?? true;
    const payload = await fetchOptionalJson<{ data: ScanRunDetail }>(`${apiBaseUrl}/api/v1/scans/runs/${scanRunId}`, undefined, authToken);

    if (!payload) {
      return null;
    }

    if (accessDeniedRef.current) return null;
    setSelectedRun(payload.data);
    if (refreshProgress) {
      try {
        await loadScanRunProgress(scanRunId);
      } catch (error) {
        if (isAuthenticationFailure(error) || isAuthorizationFailure(error)) throw error;
        // Detail evidence remains usable even when progress persistence is temporarily unavailable.
      }
    }
    return payload.data;
  }

  async function refreshScanRuns(preferredScanRunId?: string) {
    setLoadingRuns(true);

    try {
      const payload = await fetchJson<{ data: ScanRunSummary[] }>(`${apiBaseUrl}/api/v1/scans/runs`, undefined, authToken);
      if (accessDeniedRef.current) return;
      setScanRuns(payload.data);

      const nextScanRunId = preferredScanRunId ?? selectedRun?.id ?? payload.data[0]?.id;

      if (nextScanRunId) {
        await Promise.all([loadScanRunDetail(nextScanRunId, { refreshProgress: false }), loadScanRunProgress(nextScanRunId)]);
      } else {
        setSelectedRun(null);
      }
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setScanResult({
        mode: "plan",
        status: "error",
        message: userFacingErrorMessage(error, copy.messages.loadRunsFailed)
      });
    } finally {
      setLoadingRuns(false);
    }
  }

  async function pollScanRun(scanRunId: string) {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      await delay(1500);

      let detail: ScanRunDetail | null;
      let progress: ScanRunProgress | null = null;

      try {
        [progress, detail] = await Promise.all([
          loadScanRunProgress(scanRunId),
          loadScanRunDetail(scanRunId, { refreshProgress: false })
        ]);
      } catch (error) {
        if (handleApiAccessFailure(error)) return;
        setScanResult((current) =>
          current.scanRunId === scanRunId
            ? {
                ...current,
                status: "error",
                message: userFacingErrorMessage(error, copy.messages.loadEvidenceFailed)
              }
            : current
        );
        return;
      }

      if (detail && ["completed", "failed", "cancelled"].includes(detail.status)) {
        await refreshScanRuns(scanRunId);
        setScanResult((current) =>
          current.scanRunId === scanRunId
            ? {
                ...current,
                status: "success",
                message: copy.messages.scanFinished(gateDisplayLabel(detail.gateResult, locale)),
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
              gate: progress?.gateResult ?? current.gate,
              stepCount: progress?.totalSteps ?? current.stepCount,
              message: progress
                ? copy.messages.scanProgress(progress.completedSteps, progress.totalSteps, statusDisplayLabel(progress.status, locale))
                : copy.messages.scanQueuedWaiting
            }
          : current
      );
    }

    await refreshScanRuns(scanRunId);
    setScanResult((current) =>
      current.scanRunId === scanRunId
        ? {
            ...current,
            message: copy.messages.scanQueuedNoEvidence
          }
        : current
    );
  }

  async function refreshDoctor() {
    if (!authReady) {
      setScanResult({
        mode: "plan",
        status: "error",
        message: copy.messages.authRequiredDoctor
      });
      return;
    }

    setLoadingDoctor(true);

    try {
      const payload = await fetchJson<ToolchainDoctor>(`${apiBaseUrl}/api/v1/toolchain/doctor`, undefined, authToken);
      if (accessDeniedRef.current) return;
      setDoctor(payload);
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setScanResult({
        mode: "plan",
        status: "error",
        message: userFacingErrorMessage(error, copy.messages.doctorFailed)
      });
    } finally {
      setLoadingDoctor(false);
    }
  }

  async function refreshAkbStatus() {
    try {
      const payload = await fetchJson<{ data: AkbStatus }>(`${apiBaseUrl}/api/v1/akb/status`, undefined, authToken);
      if (accessDeniedRef.current) return;
      setAkbStatus(payload.data);
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setAkbStatus(null);
      setAkbMessage(userFacingErrorMessage(error, copy.messages.akbStatusUnavailable));
    }
  }

  async function refreshCapabilityAudit() {
    try {
      const payload = await fetchJson<{ data: CapabilityAudit }>(`${apiBaseUrl}/api/v1/capabilities`, undefined, authToken);
      if (accessDeniedRef.current) return;
      setCapabilityAudit(payload.data);
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setCapabilityAudit(null);
    }
  }

  async function exportLatestRun(format: "PDF" | "PPTX") {
    if (!authReady) {
      setExportMessage(copy.messages.authRequiredExport);
      return;
    }

    if (!latestRun) {
      setExportMessage(copy.messages.noScanEvidence);
      return;
    }

    setExportingFormat(format);
    setExportMessage(copy.messages.generatingExport(format));

    try {
      const payload = await fetchJson<{ data: ReportExportPayload }>(`${apiBaseUrl}/api/v1/reports/export`, {
        method: "POST",
        body: JSON.stringify({
          scanRunId: latestRun.id,
          format,
          locale
        })
      }, authToken);

      if (accessDeniedRef.current) return;
      downloadBase64File(payload.data.fileName, payload.data.mimeType, payload.data.content);
      setExportMessage(copy.messages.exportGenerated(format, payload.data.fileName));
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setExportMessage(userFacingErrorMessage(error, copy.messages.exportFailed(format)));
    } finally {
      setExportingFormat(null);
    }
  }

  async function exportCodexRemediation() {
    if (!authReady) {
      setCodexMessage(copy.messages.authRequiredExport);
      return;
    }

    if (!latestRun) {
      setCodexMessage(copy.messages.noScanEvidence);
      return;
    }

    setExportingCodex(true);
    setCodexMessage(copy.messages.generatingCodex);

    try {
      const payload = await fetchJson<{ data: CodexRemediationExportPayload }>(
        `${apiBaseUrl}/api/v1/reports/codex-remediation`,
        {
          method: "POST",
          body: JSON.stringify({
            scanRunId: latestRun.id,
            locale
          })
        },
        authToken
      );

      if (accessDeniedRef.current) return;
      downloadBase64File(payload.data.fileName, payload.data.mimeType, payload.data.content);
      setCodexMessage(copy.messages.codexGenerated(payload.data.fileName));
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setCodexMessage(userFacingErrorMessage(error, copy.messages.codexFailed));
    } finally {
      setExportingCodex(false);
    }
  }

  async function askAkb() {
    if (!authReady) {
      setAkbMessage(copy.messages.authRequiredAkb);
      return;
    }

    if (!latestRun) {
      setAkbMessage(copy.messages.noScanEvidence);
      return;
    }

    setAkbLoading(true);
    setAkbAnswer(null);
    setAkbMessage(copy.messages.askingAkb);

    try {
      const payload = await fetchJson<{ data: AkbAnswer }>(`${apiBaseUrl}/api/v1/akb/ai/ask`, {
        method: "POST",
        body: JSON.stringify({
          scanRunId: latestRun.id,
          question: akbQuestion,
          answerMode: "security_preflight_brief",
          responseLanguage: locale
        })
      }, authToken);

      if (accessDeniedRef.current) return;
      setAkbAnswer(payload.data);
      setAkbMessage(payload.data.noAnswer ? copy.messages.akbNoAnswer : copy.messages.akbCited);
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setAkbMessage(userFacingErrorMessage(error, copy.messages.akbFailed));
    } finally {
      setAkbLoading(false);
    }
  }

  async function updateFindingTriageState(findingId: string, status: FindingTriageStatus) {
    if (!authReady) {
      setScanResult((current) => ({
        ...current,
        status: "error",
        message: copy.messages.authRequiredScan
      }));
      return;
    }

    if (!selectedRun) {
      setScanResult((current) => ({
        ...current,
        status: "error",
        message: copy.messages.noScanEvidence
      }));
      return;
    }

    setTriagingFindingId(findingId);

    try {
      await fetchJson<{ data: ScanRunDetail["findings"][number] }>(
        `${apiBaseUrl}/api/v1/scans/runs/${selectedRun.id}/findings/${findingId}/triage`,
        {
          method: "PATCH",
          body: JSON.stringify({
            status
          })
        },
        authToken
      );
      if (accessDeniedRef.current) return;
      await loadScanRunDetail(selectedRun.id);
      setScanResult((current) => ({
        ...current,
        message: copy.messages.triageUpdated(copy.scanLog.triageLabel(status))
      }));
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setScanResult((current) => ({
        ...current,
        status: "error",
        message: userFacingErrorMessage(error, copy.messages.triageFailed)
      }));
    } finally {
      setTriagingFindingId(null);
    }
  }

  async function runScan(mode: "plan" | "queue") {
    if (!authReady) {
      setScanResult({
        mode,
        status: "error",
        message: copy.messages.authRequiredScan
      });
      return;
    }

    const trimmedWebTargetUrl = webTargetUrl.trim();
    const webTargetHost = scanTargetMode === "web" ? hostFromUrl(trimmedWebTargetUrl) : null;

    if (scanTargetMode === "web" && (!trimmedWebTargetUrl || !webTargetHost)) {
      setScanResult({
        mode,
        status: "error",
        message: trimmedWebTargetUrl ? copy.messages.webTargetInvalid : copy.messages.webTargetRequired
      });
      return;
    }

    if (mode === "queue" && queueRequiresWebTarget) {
      setScanResult({
        mode: "plan",
        status: "success",
        message: copy.messages.activeProfileNeedsWebTarget,
        blocked: true,
        blockedReasons: [copy.messages.activeProfileNeedsWebTargetReason],
        gate: "blocked",
        stepCount: selectedProfile?.checks.length
      });
      return;
    }

    const scanRunId = `scan_ui_${Date.now().toString(36)}`;
    setScanResult({
      mode,
      status: "loading",
      message: mode === "plan" ? copy.messages.buildingPlan : copy.messages.queueingScan,
      scanRunId
    });

    try {
      if (scanTargetMode === "web" && selectedProject && trimmedWebTargetUrl && selectedProject.publicUrl !== trimmedWebTargetUrl) {
        void saveProjectPublicUrl(selectedProject.id, trimmedWebTargetUrl);
      }

      const requestBody = {
        scanRunId,
        profileId: effectiveProfileId,
        reportsRoot: "/reports",
        project: {
          id: activeScanProject.id,
          name: activeScanProject.name,
          path: activeScanProject.path,
          dataClassification: activeScanProject.dataClassification
        },
        ...(scanTargetMode === "web" && webTargetHost
          ? {
              dast: {
                targetUrl: trimmedWebTargetUrl,
                allowedHosts: [webTargetHost],
                allowActiveScan: true,
                allowProductionTargets: false
              }
            }
          : {})
      };
      const endpoint = mode === "plan" ? "plan" : "queue";
      const payload = await fetchJson<any>(`${apiBaseUrl}/api/v1/scans/${endpoint}`, {
        method: "POST",
        body: JSON.stringify(requestBody)
      }, authToken);
      const plan = mode === "queue" ? payload.data.plan : payload;

      if (accessDeniedRef.current) return;
      setScanResult({
        mode,
        status: "success",
        message:
          mode === "plan"
            ? plan.blocked
              ? copy.messages.planBlocked
              : copy.messages.planReady
            : copy.messages.scanQueued,
        scanRunId,
        blocked: plan.blocked,
        gate: mode === "queue" ? "queued" : plan.blocked ? "blocked" : "ready",
        stepCount: plan.steps?.length ?? 0
      });

      if (mode === "queue") {
        void pollScanRun(scanRunId);
      }
    } catch (error) {
      if (handleApiAccessFailure(error)) return;

      if (error instanceof ApiRequestError && error.code === "SCAN_PLAN_BLOCKED") {
        const plan = scanPlanFromApiError(error);
        const blockedReasons = extractBlockedReasons(plan);
        setScanResult({
          mode: "plan",
          status: "success",
          message: blockedReasons.length ? copy.messages.planBlockedWithReasons(blockedReasons.slice(0, 3).join(" ")) : copy.messages.planBlocked,
          scanRunId,
          blocked: true,
          blockedReasons,
          gate: "blocked",
          stepCount: Array.isArray(plan?.steps) ? plan.steps.length : undefined
        });
        return;
      }

      setScanResult({
        mode,
        status: "error",
        message: userFacingErrorMessage(error, copy.messages.scanActionFailed),
        scanRunId
      });
    }
  }

  async function saveProjectPublicUrl(projectId: string, publicUrl: string) {
    if (!authReady) {
      return;
    }

    try {
      const payload = await fetchJson<{ data: RegisteredProject }>(`${apiBaseUrl}/api/v1/projects/${encodeURIComponent(projectId)}`, {
        method: "PATCH",
        body: JSON.stringify({ publicUrl })
      }, authToken);

      if (accessDeniedRef.current) return;
      setProjects((current) => current.map((project) => (project.id === projectId ? payload.data : project)));
      setProjectMessage(copy.projects.publicUrlSaved(payload.data.name));
    } catch (error) {
      if (handleApiAccessFailure(error)) return;
      setProjectMessage(userFacingErrorMessage(error, copy.projects.publicUrlSaveFailed));
    }
  }

  function openScanLog() {
    setScanLogOpen(true);

    if (scanResult.scanRunId) {
      void refreshScanRuns(scanResult.scanRunId);
      return;
    }

    if (latestRun?.id) {
      void loadScanRunDetail(latestRun.id);
    }
  }

  function selectSidebarItem(itemId: string) {
    if (isWorkspaceView(itemId)) {
      selectWorkspaceView(itemId);
    }
  }

  function renderSidebarMiniActions(itemId: string, disabled?: boolean) {
    if (disabled) return null;

    return (
      <span className="security-sidebar-item-actions" aria-label={copy.sidebar.itemActions}>
        <button
          type="button"
          className="security-sidebar-mini-button"
          title={copy.sidebar.openItem}
          aria-label={copy.sidebar.openItem}
          onClick={(event) => {
            event.stopPropagation();
            selectSidebarItem(itemId);
          }}
        >
          <ChevronRight size={13} aria-hidden="true" />
        </button>
        {itemId === "new-scan" ? (
          <button
            type="button"
            className="security-sidebar-mini-button"
            title={copy.sidebar.runScanItem}
            aria-label={copy.sidebar.runScanItem}
            disabled={!authReady}
            onClick={(event) => {
              event.stopPropagation();
              selectWorkspaceView("new-scan");
              void runScan("queue");
            }}
          >
            <Play size={13} aria-hidden="true" />
          </button>
        ) : null}
        {itemId === "dashboard" ? (
          <button
            type="button"
            className="security-sidebar-mini-button"
            title={copy.sidebar.refreshData}
            aria-label={copy.sidebar.refreshData}
            onClick={(event) => {
              event.stopPropagation();
              void refreshProjects();
              void refreshScanRuns();
            }}
          >
            <RefreshCw size={13} aria-hidden="true" />
          </button>
        ) : null}
        {itemId === "capabilities" ? (
          <button
            type="button"
            className="security-sidebar-mini-button"
            title={copy.sidebar.openDetail}
            aria-label={copy.sidebar.openDetail}
            onClick={(event) => {
              event.stopPropagation();
              selectWorkspaceView("capabilities");
              setDetailOpen(true);
            }}
          >
            <AlertTriangle size={13} aria-hidden="true" />
          </button>
        ) : null}
        {itemId === "execution" ? (
          <button
            type="button"
            className="security-sidebar-mini-button"
            title={copy.sidebar.dryRunItem}
            aria-label={copy.sidebar.dryRunItem}
            disabled={!authReady}
            onClick={(event) => {
              event.stopPropagation();
              selectWorkspaceView("execution");
              void runScan("plan");
            }}
          >
            <ClipboardList size={13} aria-hidden="true" />
          </button>
        ) : null}
      </span>
    );
  }

  function renderSidebarNav() {
    const activeNavGroup = navGroups.find((group) => group.id === activeRailPanel) ?? navGroups[0]!;

    return (
      <nav className="security-sidebar-nav" aria-label={copy.sidebar.workspaceMenu}>
        <section className="security-sidebar-panel-content" key={activeNavGroup.id} aria-label={activeNavGroup.label}>
          <div className="security-sidebar-panel-heading">
            <span>{activeNavGroup.label}</span>
            {activeNavGroup.id === "security" && criticalGaps ? <Badge tone="danger">{criticalGaps}</Badge> : null}
          </div>
          <div className="security-sidebar-nav-items">
            {activeNavGroup.items.map((item) => (
              <div
                key={`${activeNavGroup.id}-${item.id}`}
                className={`security-sidebar-nav-row${item.active ? " is-active" : ""}${item.disabled ? " is-disabled" : ""}`}
              >
                <button
                  type="button"
                  className="security-sidebar-nav-item"
                  disabled={item.disabled}
                  title={item.disabled ? item.disabledReason : item.label}
                  aria-current={item.active ? "page" : undefined}
                  onClick={() => selectSidebarItem(item.id)}
                >
                  <span className="security-sidebar-nav-icon">{item.icon}</span>
                  <span className="security-sidebar-nav-label">{item.label}</span>
                  {item.badge ? <Badge tone="danger">{item.badge}</Badge> : null}
                </button>
                {renderSidebarMiniActions(item.id, item.disabled)}
              </div>
            ))}
          </div>
        </section>
      </nav>
    );
  }

  function renderReportCenter() {
    const evidence = latestRun?.evidence ?? null;
    const reportItems = [
      {
        id: "markdown-report",
        title: copy.execution.markdownReport,
        fileName: "report.md",
        available: Boolean(evidence?.hasMarkdownReport),
        leading: <ScrollText size={15} />
      },
      {
        id: "json-report",
        title: copy.execution.jsonReport,
        fileName: "report.json",
        available: Boolean(evidence?.hasJsonReport),
        leading: <FileJson size={15} />
      },
      {
        id: "sarif-report",
        title: copy.execution.sarifReport,
        fileName: "results.sarif",
        available: Boolean(evidence?.hasSarifReport),
        leading: <FileWarning size={15} />
      },
      {
        id: "central-envelope",
        title: copy.execution.centralEnvelope,
        fileName: "central-result-envelope.json",
        available: Boolean(evidence?.hasCentralEnvelope),
        leading: <Archive size={15} />
      },
      {
        id: "delivery-manifest",
        title: copy.execution.deliveryManifest,
        fileName: "delivery-manifest.json",
        available: Boolean(evidence?.hasCentralTelemetryDelivery || evidence?.hasDefectDojoDelivery),
        leading: <Database size={15} />
      }
    ];

    return (
      <StructuredList
        title={copy.execution.reportCenter}
        description={exportingFormat ? copy.execution.exporting(exportingFormat) : latestRun ? exportMessage : copy.execution.reportRunMissing}
        count={
          <Badge tone={latestRun ? (reportArtifactCount >= 3 ? "good" : "warning") : "neutral"}>
            {latestRun ? `${reportArtifactCount}/${reportArtifactTotal}` : copy.execution.notLoaded}
          </Badge>
        }
        toolbar={
          <span className="security-toolbar-actions">
            <IconButton
              disabled={!latestRun || exportingFormat !== null || !authReady}
              label={copy.execution.exportPdfLabel}
              size="compact"
              title={copy.execution.exportPdfTitle}
              onClick={() => exportLatestRun("PDF")}
            >
              <FileText size={14} />
            </IconButton>
            <IconButton
              disabled={!latestRun || exportingFormat !== null || !authReady}
              label={copy.execution.exportPptxLabel}
              size="compact"
              title={copy.execution.exportPptxTitle}
              onClick={() => exportLatestRun("PPTX")}
            >
              <Presentation size={14} />
            </IconButton>
            <IconButton
              disabled={!latestRun || exportingCodex || !authReady}
              label={copy.execution.exportCodexLabel}
              size="compact"
              title={copy.execution.exportCodexTitle}
              onClick={exportCodexRemediation}
            >
              <Sparkles size={14} />
            </IconButton>
          </span>
        }
        items={reportItems.map((item) => ({
          id: item.id,
          title: item.title,
          leading: item.leading,
          badges: (
            <Badge tone={item.available ? "good" : "warning"}>
              {item.available ? copy.execution.reportReady : copy.execution.reportMissing}
            </Badge>
          ),
          meta:
            item.available && evidence
              ? copy.execution.reportEvidenceMeta(evidence.root, item.fileName)
              : copy.execution.reportEvidenceMissingMeta
        }))}
        ariaLabel={copy.execution.reportCenterAria}
        className="security-list-card"
      />
    );
  }

  function renderNewScan() {
    const trimmedWebTarget = webTargetUrl.trim();
    const targetValue = scanTargetMode === "web" ? trimmedWebTarget || copy.runPanel.webTargetPlaceholder : activeScanProject.path;
    const targetReady = scanTargetMode === "project" ? Boolean(activeScanProject.path) : Boolean(hostFromUrl(trimmedWebTarget));
    const selectedProfileNeedsWeb = selectedProfile?.allowActiveDast === true;
    const selectedProfileCheckCount = selectedProfile?.checks.length ?? 0;
    const planReady = scanResult.status === "success" && scanResult.mode === "plan" && !scanResult.blocked;
    const queuedOrRunning = Boolean(scanResult.scanRunId && (scanResult.mode === "queue" || scanResult.status === "loading"));
    const codexReady = Boolean(latestRun);
    const latestEvidenceCount = latestRun?.evidence.files.length ?? 0;
    const stepItems = [
      {
        id: "target",
        title: copy.newScan.stepTarget,
        leading: scanTargetMode === "web" ? <Globe2 size={15} /> : <FolderGit2 size={15} />,
        badges: <Badge tone={targetReady ? "good" : "warning"}>{targetReady ? translateStatus(locale, "ready") : translateStatus(locale, "missing")}</Badge>,
        meta: targetValue
      },
      {
        id: "profile",
        title: copy.newScan.stepProfile,
        leading: <ClipboardList size={15} />,
        badges: <Badge tone="info">{copy.newScan.profileChecks(selectedProfileCheckCount)}</Badge>,
        meta: selectedProfile ? profileName(locale, selectedProfile.id, selectedProfile.name) : copy.execution.loadProfile
      },
      {
        id: "plan",
        title: copy.newScan.stepPlan,
        leading: <ShieldCheck size={15} />,
        badges: <Badge tone={planReady ? "good" : scanResult.blocked ? "danger" : "neutral"}>{scanResult.gate ? actionGateDisplayLabel(scanResult.gate, locale) : translateStatus(locale, "idle")}</Badge>,
        meta: scanResult.stepCount != null ? copy.runPanel.plannedSteps(scanResult.stepCount) : copy.newScan.planPending
      },
      {
        id: "codex",
        title: copy.newScan.stepCodex,
        leading: <Sparkles size={15} />,
        badges: <Badge tone={codexReady ? "good" : "neutral"}>{codexReady ? translateStatus(locale, "ready") : translateStatus(locale, "empty")}</Badge>,
        meta: latestRun ? `${latestRun.id} · ${copy.execution.findingsCount(latestRun.findingCount)}` : copy.newScan.codexPending
      }
    ];
    const activeRunId = scanResult.scanRunId ?? selectedRun?.id ?? latestRun?.id;
    const activeRunDetail = selectedRun?.id === activeRunId ? selectedRun : null;
    const activeProgress = scanProgress?.scanRunId === activeRunId ? scanProgress : null;
    const liveTotalSteps = activeProgress?.totalSteps ?? activeRunDetail?.steps.length ?? scanResult.stepCount ?? selectedProfile?.checks.length ?? 0;
    const liveCompletedSteps = activeProgress?.completedSteps ?? (activeRunDetail ? completedStepCount(activeRunDetail.steps) : scanResult.status === "success" ? liveTotalSteps : 0);
    const liveProgressValue = progressValue(liveCompletedSteps, liveTotalSteps, activeProgress?.status ?? activeRunDetail?.status ?? scanResult.status);
    const liveStatus = activeProgress?.status ?? activeRunDetail?.status ?? scanResult.status;
    const scanIsActive = scanResult.status === "loading" || ["queued", "running"].includes(liveStatus.toLowerCase());
    const scanQueueDisabled = scanResult.status === "loading" || !authReady || queueRequiresWebTarget || (selectedProfileNeedsWeb && scanTargetMode === "web" && !targetReady);
    const scanResultTone = queueRequiresWebTarget || scanResult.blocked ? "warning" : statusTone(scanResult.status);
    const scanResultLabel = queueRequiresWebTarget
      ? gateDisplayLabel("warning", locale)
      : scanResult.blocked
        ? actionGateDisplayLabel("blocked", locale)
        : scanResult.status === "loading"
          ? copy.runPanel.working
          : statusDisplayLabel(scanResult.status, locale);
    const scanResultMessage = queueRequiresWebTarget ? copy.messages.activeProfileNeedsWebTarget : scanResult.message;
    const displayedBlockedReasons = queueRequiresWebTarget ? [copy.messages.activeProfileNeedsWebTargetReason] : (scanResult.blockedReasons ?? []);
    const liveStepItems = activeRunDetail?.steps.length
      ? activeRunDetail.steps.slice(0, 8).map((step) => ({
          id: step.stepId,
          title: step.checkId,
          status: step.status,
          statusLabel: statusDisplayLabel(step.status, locale),
          findingLabel: step.findingCount ? copy.execution.findingsCount(step.findingCount) : undefined
        }))
      : (selectedProfile?.checks ?? []).slice(0, 8).map((check, index) => ({
          id: `${check}-${index}`,
          title: check,
          status: scanIsActive && index === 0 ? "running" : "pending",
          statusLabel: statusDisplayLabel(scanIsActive && index === 0 ? "running" : "pending", locale)
        }));
    const akbInlineMeta = akbLoading
      ? copy.messages.askingAkb
      : akbAnswer?.answer ?? akbMessage;

    return (
      <div className="security-view-stack">
        <section className="security-new-scan-hero" aria-label={copy.newScan.title}>
          <div>
            <span>{copy.views.security}</span>
            <h2>{copy.newScan.title}</h2>
            <p>{copy.newScan.subtitle}</p>
          </div>
          <div className="security-new-scan-hero-actions">
            <Button disabled={loadingProjects || !authReady} onClick={refreshProjects} size="compact">
              <RefreshCw size={14} />
              {loadingProjects ? copy.dashboard.loadingProjects : copy.projects.refresh}
            </Button>
            <Button disabled={loadingRuns} onClick={() => refreshScanRuns(latestRun?.id)} size="compact">
              <History size={14} />
              {copy.execution.refresh}
            </Button>
          </div>
        </section>

        <section className="security-flow-strip" aria-label={copy.newScan.workflow}>
          {stepItems.map((item) => (
            <div key={item.id} className="security-flow-step">
              <span className="security-flow-icon">{item.leading}</span>
              <span>
                <strong>{item.title}</strong>
                <small>{item.meta}</small>
              </span>
              {item.badges}
            </div>
          ))}
        </section>

        <div className="security-new-scan-layout">
          <DataGridShell
            title={<strong>{copy.newScan.scanComposer}</strong>}
            toolbar={<Badge tone={targetReady ? "good" : "warning"}>{targetReady ? copy.newScan.readyToRun : translateStatus(locale, "missing")}</Badge>}
            className="security-grid-shell"
          >
            <div className="security-scan-composer">
              <div className="security-scan-composer-grid">
                <section className="security-scan-composer-section">
                  <div className="security-section-heading">
                    <FolderGit2 size={16} aria-hidden="true" />
                    <strong>{copy.newScan.target}</strong>
                  </div>
                  <div className="security-target-mode" role="group" aria-label={copy.runPanel.targetType}>
                    <button
                      type="button"
                      className={scanTargetMode === "project" ? "is-active" : undefined}
                      aria-pressed={scanTargetMode === "project"}
                      onClick={() => {
                        setScanTargetMode("project");
                        setSelectedProfileId("documentation-compliance");
                      }}
                    >
                      <FolderGit2 size={14} aria-hidden="true" />
                      {copy.runPanel.directoryTarget}
                    </button>
                    <button
                      type="button"
                      className={scanTargetMode === "web" ? "is-active" : undefined}
                      aria-pressed={scanTargetMode === "web"}
                      onClick={() => {
                        setScanTargetMode("web");
                        if (selectedProjectPublicUrl) {
                          setWebTargetUrl(selectedProjectPublicUrl);
                        }
                        setSelectedProfileId("web-perimeter-safe");
                      }}
                    >
                      <Globe2 size={14} aria-hidden="true" />
                      {copy.runPanel.webTarget}
                    </button>
                  </div>

                  {scanTargetMode === "project" ? (
                    <ProjectPicker
                      label={copy.projects.selectProject}
                      labels={{
                        title: copy.projects.selectProject,
                        search: copy.projects.selectProject,
                        placeholder: copy.projects.noSelectedProject,
                        empty: copy.projects.noSelectedProject,
                        close: copy.detail.close
                      }}
                      projects={projectPickerProjects}
                      selectedProjectId={selectedProject?.id ?? null}
                      disabled={!projects.length}
                      onProjectSelect={(projectId) => setSelectedProjectId(projectId)}
                      footer={<HelpHint label={copy.projects.selectProject} text={copy.runPanel.directoryTargetHelp} />}
                      popoverPlacement="bottom-start"
                    />
                  ) : (
                    <div className="security-url-field">
                      <FieldLabelWithHelp
                        htmlFor="security-web-target-url"
                        label={copy.runPanel.webTargetUrl}
                        helpLabel={copy.runPanel.webTargetUrl}
                        helpText={copy.runPanel.webTargetHelp}
                      />
                      <input
                        id="security-web-target-url"
                        value={webTargetUrl}
                        onChange={(event) => setWebTargetUrl(event.currentTarget.value)}
                        placeholder={copy.runPanel.webTargetPlaceholder}
                        inputMode="url"
                        autoComplete="url"
                      />
                      {selectedProject ? (
                        <p className="security-url-memory">
                          {selectedProject.publicUrl
                            ? copy.runPanel.savedWebTarget(selectedProject.publicUrl)
                            : copy.runPanel.publicUrlWillBeSaved(selectedProject.name)}
                        </p>
                      ) : null}
                    </div>
                  )}
                </section>

                <section className="security-scan-composer-section">
                  <div className="security-section-heading">
                    <ClipboardList size={16} aria-hidden="true" />
                    <strong>{copy.newScan.scanControl}</strong>
                  </div>
                  <SelectField
                    label={copy.runPanel.scanProfile}
                    description={selectedProfileDescription}
                    labelAccessory={<Badge tone="info">{copy.newScan.profileChecks(selectedProfileCheckCount)}</Badge>}
                    value={effectiveProfileId}
                    onChange={(event) => {
                      const nextProfileId = event.currentTarget.value;
                      setSelectedProfileId(nextProfileId);
                      const nextProfile = profiles.find((profile) => profile.id === nextProfileId);
                      if (nextProfile?.allowActiveDast) {
                        setScanTargetMode("web");
                        if (selectedProjectPublicUrl) {
                          setWebTargetUrl(selectedProjectPublicUrl);
                        }
                      }
                    }}
                    searchPlaceholder={copy.runPanel.findProfile}
                  >
                    {profileOptions.map((profile) => (
                      <option key={profile.id} value={profile.id}>
                        {profileName(locale, profile.id, profile.name)}
                      </option>
                    ))}
                  </SelectField>
                </section>
              </div>

              <div className="security-facts security-facts-inline">
                <div>
                  <span>{copy.newScan.selectedTarget}</span>
                  <strong>{targetValue}</strong>
                </div>
                <div>
                  <span>{copy.runPanel.checks}</span>
                  <strong>{selectedProfileCheckCount}</strong>
                </div>
                <div>
                  <span>{copy.projects.dataClassification}</span>
                  <strong>{copy.projects.classifications[activeScanProject.dataClassification]}</strong>
                </div>
                <div>
                  <span>{copy.runPanel.tools}</span>
                  <strong>{healthcareDoctor ? copy.runPanel.healthcareReady(healthcareDoctor.available) : copy.runPanel.notChecked}</strong>
                </div>
              </div>

              {selectedProjectPolicy ? (
                <InformationPolicyPanel
                  value={selectedProjectPolicy}
                  title={locale === "cs" ? "Informační policy projektu" : "Project information policy"}
                  accessExplanation={locale === "cs"
                    ? "Přístup k bezpečnostním důkazům vyžaduje aktivní oprávnění SecurityPreflight, přesný projektový scope a soulad s touto centrálně registrovanou policy. SecurityPreflight neposkytuje anonymní veřejnou publikaci."
                    : "Security evidence requires active SecurityPreflight access, the exact project scope, and compliance with this centrally registered policy. SecurityPreflight does not provide anonymous public publication."}
                  compact
                />
              ) : null}

              <div className="security-scan-command-row">
                <div className="security-actions">
                  <Button variant="primary" disabled={scanQueueDisabled} onClick={() => runScan("queue")}>
                    <Play size={14} />
                    {copy.runPanel.runScan}
                  </Button>
                  <Button disabled={scanResult.status === "loading" || !authReady} onClick={() => runScan("plan")}>
                    <ClipboardList size={14} />
                    {copy.runPanel.dryRun}
                  </Button>
                  <Button disabled={!scanResult.scanRunId && !latestRun} onClick={openScanLog}>
                    <TerminalSquare size={14} />
                    {copy.runPanel.openScanLog}
                  </Button>
                  <Button onClick={() => setDetailOpen(true)}>
                    <AlertTriangle size={14} />
                    {copy.runPanel.showBlockers}
                  </Button>
                </div>
                <div className="security-result" data-tone={scanResultTone} role="status">
                  <strong>{scanResultLabel}</strong>
                  <p>{scanResultMessage}</p>
                  {selectedProfileNeedsWeb && scanTargetMode === "web" && !targetReady ? (
                    <p>{copy.runPanel.nextStepAddPublicUrl}</p>
                  ) : null}
                  {scanResult.scanRunId ? <code>{scanResult.scanRunId}</code> : null}
                  {scanResult.stepCount != null ? <span>{copy.runPanel.plannedSteps(scanResult.stepCount)}</span> : null}
                  {displayedBlockedReasons.length ? (
                    <ul className="security-result-reasons">
                      {displayedBlockedReasons.slice(0, 3).map((reason) => (
                        <li key={reason}>{reason}</li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              </div>
            </div>
          </DataGridShell>

          <ScanProgressPanel
            title={copy.newScan.liveProgress}
            badgeTone={scanIsActive ? "warning" : activeRunDetail ? statusTone(activeRunDetail.gateResult) : "neutral"}
            badgeLabel={scanIsActive ? copy.newScan.runningNow : copy.newScan.lastRun}
            scanIsActive={scanIsActive}
            activeRunId={activeRunId ?? copy.newScan.noRun}
            completedLabel={copy.scanLog.completedSteps(liveCompletedSteps, liveTotalSteps)}
            progressValue={liveProgressValue}
            progressTone={liveProgressValue === 100 ? "good" : "warning"}
            progressLabel={copy.scanLog.progress}
            steps={liveStepItems}
            latestOutcomeLabel={copy.newScan.latestOutcome}
            findingsTitle={copy.scanLog.persistedFindings}
            findingsValue={copy.execution.findingsCount(latestRun?.findingCount ?? 0)}
            findingsMeta={latestRun ? profileName(locale, latestRun.profile.id, latestRun.profile.name) : copy.execution.selectScanForDetail}
            evidenceTitle={copy.newScan.evidence}
            evidenceValue={String(latestEvidenceCount)}
            evidenceMeta={latestRun?.evidence.root ?? "/reports"}
            codexTitle={copy.newScan.redactedMarkdown}
            codexValue={codexReady ? translateStatus(locale, "ready") : translateStatus(locale, "empty")}
            codexMeta={exportingCodex ? copy.messages.generatingCodex : codexMessage}
            akbTitle={copy.telemetry.akbIntegration}
            akbValue={akbStatus?.configured ? translateStatus(locale, "configured") : translateStatus(locale, "not configured")}
            akbMeta={akbInlineMeta}
            openExecutionLabel={copy.scanLog.openExecution}
            exportCodexLabel={copy.newScan.exportCodex}
            askAkbLabel={copy.telemetry.askAkb}
            askAkbBusyLabel={copy.telemetry.askingAkb}
            canOpenExecution={Boolean(latestRun)}
            canExportCodex={Boolean(latestRun) && authReady}
            canAskAkb={Boolean(latestRun) && authReady && Boolean(akbStatus?.configured)}
            exportingCodex={exportingCodex}
            askingAkb={akbLoading}
            onOpenExecution={() => selectWorkspaceView("execution")}
            onExportCodex={exportCodexRemediation}
            onAskAkb={askAkb}
          />
        </div>

        <section className={`security-register-drawer${projectRegistryOpen ? " is-open" : ""}`}>
          <div className="security-register-summary">
            <button
              type="button"
              className="security-register-toggle"
              aria-expanded={projectRegistryOpen}
              onClick={() => setProjectRegistryOpen((open) => !open)}
            >
              <ChevronRight size={15} aria-hidden="true" />
              <span>
                <strong>{copy.newScan.projectRegistry}</strong>
                <small>{copy.newScan.projectRegistryDescription}</small>
              </span>
            </button>
            <Button
              disabled={loadingProjects || !authReady}
              onClick={() => {
                void refreshProjects();
              }}
              size="compact"
            >
              <History size={14} />
              {copy.projects.refresh}
            </Button>
          </div>
          {projectRegistryOpen ? (
            <div className="security-project-form security-project-form-compact security-register-body">
              <label className="security-akb-question" htmlFor="new-project-name">
                <span>{copy.projects.name}</span>
                <input
                  id="new-project-name"
                  aria-label={copy.projects.name}
                  value={projectForm.name}
                  onChange={(event) => setProjectForm((current) => ({ ...current, name: event.currentTarget.value }))}
                  autoComplete="off"
                />
              </label>
              <label className="security-akb-question security-project-path" htmlFor="new-project-path">
                <span>{copy.projects.path}</span>
                <input
                  id="new-project-path"
                  aria-label={copy.projects.path}
                  value={projectForm.path}
                  onChange={(event) => setProjectForm((current) => ({ ...current, path: event.currentTarget.value }))}
                  autoComplete="off"
                />
              </label>
              <label className="security-akb-question" htmlFor="new-project-data-classification">
                <span>{copy.projects.dataClassification}</span>
                <select
                  id="new-project-data-classification"
                  aria-label={copy.projects.dataClassification}
                  value={projectForm.dataClassification}
                  onChange={(event) => {
                    const value = event.currentTarget.value as RegisteredProject["dataClassification"];
                    setProjectForm((current) => ({ ...current, dataClassification: value }));
                  }}
                >
                  {(["internal", "sensitive", "health-data", "confidential", "public"] as const).map((classification) => (
                    <option key={classification} value={classification}>
                      {copy.projects.classifications[classification]}
                    </option>
                  ))}
                </select>
              </label>
              <div className="security-project-form-actions">
                <Button variant="primary" disabled={registeringProject || !authReady} onClick={registerProject}>
                  <FolderGit2 size={14} />
                  {registeringProject ? copy.projects.registering : copy.projects.register}
                </Button>
                <span>{projectMessage}</span>
              </div>
            </div>
          ) : null}
        </section>

      </div>
    );
  }

  function renderDashboard() {
    return (
      <div className="security-view-stack">
        <section className="security-metric-grid" aria-label={copy.dashboard.maturityAria}>
          <MetricCard
            icon={ShieldCheck}
            label={copy.dashboard.functionalMaturity}
            value={`${maturityScore}%`}
            detail={copy.dashboard.maturityDetail(criticalGaps)}
            tone={criticalGaps ? "warning" : "good"}
            chartData={[32, 38, 42, 48, maturityScore]}
          />
          <MetricCard
            icon={ClipboardList}
            label={copy.dashboard.scanProfiles}
            value={profiles.length || "-"}
            detail={copy.dashboard.scanProfilesDetail}
            tone="info"
            chartData={[4, 5, 7, 8, profiles.length || 9]}
          />
          <MetricCard
            icon={Wrench}
            label={copy.dashboard.toolchain}
            value={healthcareDoctor ? healthcareDoctor.available : copy.dashboard.notChecked}
            detail={
              healthcareDoctor
                ? copy.dashboard.toolchainDetail(
                    healthcareDoctor.missing,
                    healthcareDoctor.error,
                    Boolean(healthcareDoctor.optionalMissing || healthcareDoctor.optionalError)
                  )
                : copy.dashboard.doctorDetail
            }
            tone={healthcareDoctor?.error || healthcareDoctor?.missing ? "danger" : doctor ? "good" : "neutral"}
            chartType="bar"
            chartData={healthcareDoctor ? [healthcareDoctor.available, healthcareDoctor.missing, healthcareDoctor.error] : undefined}
          />
          <MetricCard
            icon={FileJson}
            label={copy.dashboard.reports}
            value={latestRun ? `${reportArtifactCount}/${reportArtifactTotal}` : "PDF/PPTX"}
            detail={latestRun ? copy.dashboard.reportsEvidenceDetail(reportArtifactCount, reportArtifactTotal) : copy.dashboard.reportsDetail}
            tone={latestRun ? (reportArtifactCount >= 3 ? "good" : "warning") : "info"}
            chartData={latestRun ? [1, 2, 3, 4, reportArtifactCount] : [1, 1, 1, 1, 1]}
          />
        </section>

        <DataGridShell
          title={<strong>{copy.dashboard.projects}</strong>}
          toolbar={
            <Button disabled={loadingProjects || !authReady} onClick={refreshProjects} size="compact">
              <History size={14} />
              {loadingProjects ? copy.dashboard.loadingProjects : copy.projects.refresh}
            </Button>
          }
          className="security-grid-shell"
        >
          <div className="security-project-form">
            <label className="security-akb-question" htmlFor="project-name">
              <span>{copy.projects.name}</span>
              <input
                id="project-name"
                aria-label={copy.projects.name}
                value={projectForm.name}
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  setProjectForm((current) => ({ ...current, name: value }));
                }}
                autoComplete="off"
              />
            </label>
            <label className="security-akb-question security-project-path" htmlFor="project-path">
              <span>{copy.projects.path}</span>
              <input
                id="project-path"
                aria-label={copy.projects.path}
                value={projectForm.path}
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  setProjectForm((current) => ({ ...current, path: value }));
                }}
                autoComplete="off"
              />
            </label>
            <label className="security-akb-question" htmlFor="project-data-classification">
              <span>{copy.projects.dataClassification}</span>
              <select
                id="project-data-classification"
                aria-label={copy.projects.dataClassification}
                value={projectForm.dataClassification}
                onChange={(event) => {
                  const value = event.currentTarget.value as RegisteredProject["dataClassification"];
                  setProjectForm((current) => ({
                    ...current,
                    dataClassification: value
                  }));
                }}
              >
                {(["internal", "sensitive", "health-data", "confidential", "public"] as const).map((classification) => (
                  <option key={classification} value={classification}>
                    {copy.projects.classifications[classification]}
                  </option>
                ))}
              </select>
            </label>
            <label className="security-akb-question" htmlFor="project-owner">
              <span>{copy.projects.owner}</span>
              <input
                id="project-owner"
                aria-label={copy.projects.owner}
                value={projectForm.owner}
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  setProjectForm((current) => ({ ...current, owner: value }));
                }}
                autoComplete="off"
              />
            </label>
            <label className="security-akb-question security-project-path" htmlFor="project-repository-url">
              <span>{copy.projects.repositoryUrl}</span>
              <input
                id="project-repository-url"
                aria-label={copy.projects.repositoryUrl}
                value={projectForm.repositoryUrl}
                onChange={(event) => {
                  const value = event.currentTarget.value;
                  setProjectForm((current) => ({ ...current, repositoryUrl: value }));
                }}
                autoComplete="off"
              />
            </label>
            <div className="security-project-form-actions">
              <Button variant="primary" disabled={registeringProject || !authReady} onClick={registerProject}>
                <FolderGit2 size={14} />
                {registeringProject ? copy.projects.registering : copy.projects.register}
              </Button>
              <span>{projectMessage}</span>
            </div>
          </div>
          <DataTable
            rows={projectRows}
            columns={projectColumns}
            getRowId={(row) => row.id}
            emptyLabel={loadingProjects ? copy.dashboard.loadingProjects : copy.dashboard.noProjects}
            aria-label={copy.dashboard.registeredProjects}
          />
        </DataGridShell>

        <div className="security-split-grid">
          <DataGridShell
            title={<strong>{copy.dashboard.recentScans}</strong>}
            toolbar={
              <Button disabled={loadingRuns} onClick={() => refreshScanRuns()} size="compact">
                <History size={14} />
                {loadingRuns ? copy.dashboard.refreshing : copy.dashboard.refresh}
              </Button>
            }
            className="security-grid-shell"
          >
            <DataTable
              rows={scanRows}
              columns={scanColumns}
              getRowId={(row) => row.id}
              emptyLabel={copy.dashboard.noCompletedEvidence}
              aria-label={copy.dashboard.recentScansAria}
            />
          </DataGridShell>

          {renderReportCenter()}

          <StructuredList
            title={copy.dashboard.toolchainDoctor}
            description={
              doctor
                ? `${copy.dashboard.checked} ${new Date(doctor.checkedAt).toLocaleTimeString(locale === "cs" ? "cs-CZ" : "en-US")}`
                : copy.dashboard.dockerScannerStack
            }
            count={
              <Badge tone={healthcareDoctor ? statusTone(healthcareDoctor.error || healthcareDoctor.missing ? "error" : "available") : "neutral"}>
                {doctor ? translateStatus(locale, "live") : translateStatus(locale, "fallback")}
              </Badge>
            }
            toolbar={
              <Button disabled={loadingDoctor} onClick={refreshDoctor} size="compact">
                <Wrench size={14} />
                {loadingDoctor ? copy.topbar.checking : copy.dashboard.check}
              </Button>
            }
            items={renderedTools.map((tool) => ({
              id: tool.name,
              title: tool.name,
              leading: <Wrench size={15} />,
              badges: <Badge tone={statusTone(tool.status)}>{translateStatus(locale, tool.status)}</Badge>,
              meta: <code>{tool.version}</code>
            }))}
            ariaLabel={copy.dashboard.toolchainDoctor}
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
            <h2>{copy.capabilities.title}</h2>
            <p>{copy.capabilities.body}</p>
          </div>
          <div className="security-progress-card">
            <span>{copy.capabilities.maturityEstimate}</span>
            <strong>{maturityScore}%</strong>
            <ProgressBar value={maturityScore} tone={criticalGaps ? "warning" : "good"} label={copy.capabilities.maturityProgress} />
          </div>
        </section>

        <DataGridShell
          title={<strong>{copy.capabilities.auditTitle}</strong>}
          toolbar={
            <span className="security-toolbar-actions">
              <SearchBox
                value={searchQuery}
                onChange={setSearchQuery}
                onClear={() => setSearchQuery("")}
                placeholder={copy.toolbar.filterCapabilities}
                variant="toolbar"
                ariaLabel={copy.toolbar.filterCapabilities}
              />
              <Badge tone={criticalGaps ? "danger" : "good"}>{copy.capabilities.p0Gaps(criticalGaps)}</Badge>
            </span>
          }
          className="security-grid-shell"
        >
          <DataTable
            rows={filteredCapabilityRows}
            columns={capabilityColumns}
            getRowId={(row) => row.id}
            emptyLabel={copy.capabilities.noMatching}
            aria-label={copy.capabilities.aria}
          />
        </DataGridShell>
      </div>
    );
  }

  function renderExecution() {
    return (
      <div className="security-view-stack">
        <StructuredList
          title={copy.execution.lifecycle}
          description={copy.execution.lifecycleDescription}
          count={<Badge tone="warning">{copy.execution.triageIncomplete}</Badge>}
          items={executionStages.map((stage) => ({
            id: stage.id,
            title: stage.title,
            leading: <RagBadge status={statusRag(stage.status)} label={statusDisplayLabel(stage.status, locale)} />,
            meta: stage.meta
          }))}
          ariaLabel={copy.execution.lifecycle}
          className="security-list-card"
        />
        <DataGridShell title={<strong>{copy.execution.plannedChecks}</strong>} className="security-grid-shell">
          <StructuredList
            items={(selectedProfile?.checks ?? []).map((check) => ({
              id: check,
              title: check,
              leading: <CheckCircle2 size={15} />,
              badges: <Badge tone="info">{copy.execution.planned}</Badge>
            }))}
            emptyLabel={copy.execution.loadProfile}
            ariaLabel={copy.execution.selectedChecks}
          />
        </DataGridShell>
        <div className="security-split-grid">
          <StructuredList
            title={copy.execution.latestEvidence}
            description={latestRun ? `${latestRun.id} · ${formatDuration(latestRun.durationMs, locale)}` : copy.execution.runScanForEvidence}
            count={
              <Badge tone={latestRun ? statusTone(latestRun.gateResult) : "neutral"}>
                {latestRun ? gateDisplayLabel(latestRun.gateResult, locale) : translateStatus(locale, "empty")}
              </Badge>
            }
            toolbar={
              <span className="security-toolbar-actions">
                <Button disabled={loadingRuns} onClick={() => refreshScanRuns(latestRun?.id)} size="compact">
                  <History size={14} />
                  {copy.execution.refresh}
                </Button>
                <IconButton
                  disabled={!latestRun || exportingFormat !== null || !authReady}
                  label={copy.execution.exportPdfLabel}
                  size="compact"
                  title={copy.execution.exportPdfTitle}
                  onClick={() => exportLatestRun("PDF")}
                >
                  <FileText size={14} />
                </IconButton>
                <IconButton
                  disabled={!latestRun || exportingFormat !== null || !authReady}
                  label={copy.execution.exportPptxLabel}
                  size="compact"
                  title={copy.execution.exportPptxTitle}
                  onClick={() => exportLatestRun("PPTX")}
                >
                  <Presentation size={14} />
                </IconButton>
                <IconButton
                  disabled={!latestRun || exportingCodex || !authReady}
                  label={copy.execution.exportCodexLabel}
                  size="compact"
                  title={copy.execution.exportCodexTitle}
                  onClick={exportCodexRemediation}
                >
                  <Sparkles size={14} />
                </IconButton>
              </span>
            }
            items={(latestRun?.evidence.files ?? []).map((file) => ({
              id: file,
              title: file,
              leading: file.endsWith(".md") ? <ScrollText size={15} /> : <FileJson size={15} />,
              badges: <Badge tone={file === "central-result-envelope.json" ? "info" : "good"}>{file.endsWith(".json") ? "json" : "markdown"}</Badge>,
              meta: copy.execution.reportsPathEvidence,
              actions: latestRun ? (
                <span className="security-hover-actions">
                  <IconButton
                    disabled={exportingFormat !== null || !authReady}
                    label={copy.execution.exportFilePdf(file)}
                    size="compact"
                    title={copy.execution.exportScanPdf}
                    onClick={() => exportLatestRun("PDF")}
                  >
                    <Download size={13} />
                  </IconButton>
                  <IconButton
                    disabled={exportingFormat !== null || !authReady}
                    label={copy.execution.exportFilePptx(file)}
                    size="compact"
                    title={copy.execution.exportScanPptx}
                    onClick={() => exportLatestRun("PPTX")}
                  >
                    <Presentation size={13} />
                  </IconButton>
                </span>
              ) : null
            }))}
            emptyLabel={copy.execution.noEvidenceFiles}
            ariaLabel={copy.execution.latestEvidenceAria}
            className="security-list-card"
          />
          <StructuredList
            title={copy.execution.latestSteps}
            description={
              selectedRun
                ? copy.execution.stepDetailDescription(selectedRun.findingCount, formatDateTime(selectedRun.finishedAt, locale))
                : copy.execution.selectScanForDetail
            }
            count={
              <Badge tone={selectedRun ? statusTone(selectedRun.status) : "neutral"}>
                {selectedRun ? translateStatus(locale, selectedRun.status) : copy.execution.notLoaded}
              </Badge>
            }
            items={(selectedRun?.steps ?? []).map((step) => ({
              id: step.stepId,
              title: step.checkId,
              leading: <RagBadge status={statusRag(step.status)} label={statusDisplayLabel(step.status, locale)} />,
              badges: step.findingCount ? (
                <Badge tone="danger">{copy.execution.findingsCount(step.findingCount)}</Badge>
              ) : (
                <Badge tone="good">{copy.execution.noFindings}</Badge>
              ),
              meta: step.evidenceFile ?? step.message ?? copy.execution.noEvidenceFile
            }))}
            emptyLabel={copy.execution.noStepDetail}
            ariaLabel={copy.execution.latestStepsAria}
            className="security-list-card"
          />
        </div>
        {renderReportCenter()}
      </div>
    );
  }

  function renderScanLogSurface() {
    const run = selectedRun ?? latestRun;
    const currentRunId = run?.id ?? scanResult.scanRunId;
    const currentServerProgress = scanProgress?.scanRunId === currentRunId ? scanProgress : null;
    const steps = selectedRun?.steps ?? [];
    const completedSteps = currentServerProgress?.completedSteps ?? completedStepCount(steps);
    const totalSteps = currentServerProgress?.totalSteps ?? (steps.length || scanResult.stepCount || 0);
    const currentProgress = progressValue(completedSteps, totalSteps, currentServerProgress?.status ?? selectedRun?.status ?? run?.status);
    const evidenceFiles = run?.evidence.files ?? [];
    const findings = selectedRun?.findings ?? [];
    const blockingReasons = selectedRun?.gate.blockingReasons ?? [];

    if (!run && !scanResult.scanRunId) {
      return (
        <div className="security-scan-log">
          <div className="security-empty-state">
            <TerminalSquare size={22} aria-hidden="true" />
            <strong>{copy.scanLog.noRun}</strong>
            <p>{copy.scanLog.noRunDescription}</p>
          </div>
        </div>
      );
    }

    return (
      <div className="security-scan-log">
        <section className="security-scan-log-hero">
          <div>
            <span>{copy.scanLog.scanRunId}</span>
            <strong>{run?.id ?? scanResult.scanRunId}</strong>
            <p>{scanResult.scanRunId === run?.id ? scanResult.message : copy.scanLog.loadedFromEvidence}</p>
          </div>
          <RagBadge
            status={statusRag(run?.gateResult ?? scanResult.gate ?? scanResult.status)}
            label={run ? gateDisplayLabel(run.gateResult, locale) : actionGateDisplayLabel(scanResult.gate ?? scanResult.status, locale)}
          />
        </section>

        <section className="security-scan-log-progress" aria-label={copy.scanLog.progress}>
          <div>
            <span>{copy.scanLog.progress}</span>
            <strong>{copy.scanLog.completedSteps(completedSteps, totalSteps)}</strong>
          </div>
          <ProgressBar value={currentProgress} tone={currentProgress === 100 ? "good" : "warning"} label={copy.scanLog.progress} />
        </section>

        <div className="security-scan-log-facts">
          <div>
            <span>{copy.scanLog.status}</span>
            <strong>{currentServerProgress ? statusDisplayLabel(currentServerProgress.status, locale) : run ? statusDisplayLabel(run.status, locale) : statusDisplayLabel(scanResult.status, locale)}</strong>
          </div>
          <div>
            <span>{copy.scanLog.project}</span>
            <strong>{run?.project.name ?? activeScanProject.name}</strong>
          </div>
          <div>
            <span>{copy.scanLog.profile}</span>
            <strong>{run ? profileName(locale, run.profile.id, run.profile.name) : profileName(locale, effectiveProfileId, effectiveProfileId)}</strong>
          </div>
          <div>
            <span>{copy.scanLog.duration}</span>
            <strong>{formatDuration(run?.durationMs ?? null, locale)}</strong>
          </div>
          <div>
            <span>{copy.scanLog.persistedFindings}</span>
            <strong>{copy.execution.findingsCount(currentServerProgress?.findingCount ?? run?.findingCount ?? 0)}</strong>
          </div>
          <div>
            <span>{copy.scanLog.evidenceRoot}</span>
            <strong>{run?.evidence.root ?? "/reports"}</strong>
          </div>
        </div>

        <div className="security-actions">
          <Button disabled={loadingRuns} onClick={() => refreshScanRuns(run?.id ?? scanResult.scanRunId)} size="compact">
            <RefreshCw size={14} />
            {loadingRuns ? copy.dashboard.refreshing : copy.scanLog.refresh}
          </Button>
          <Button
            disabled={!run}
            onClick={() => {
              selectWorkspaceView("execution");
              setScanLogOpen(false);
            }}
            size="compact"
          >
            <Archive size={14} />
            {copy.scanLog.openExecution}
          </Button>
          <IconButton disabled={!run || exportingFormat !== null || !authReady} label={copy.scanLog.exportPdf} title={copy.scanLog.exportPdf} onClick={() => exportLatestRun("PDF")} size="compact">
            <FileText size={14} />
          </IconButton>
          <IconButton disabled={!run || exportingFormat !== null || !authReady} label={copy.scanLog.exportPptx} title={copy.scanLog.exportPptx} onClick={() => exportLatestRun("PPTX")} size="compact">
            <Presentation size={14} />
          </IconButton>
          <IconButton disabled={!run || exportingCodex || !authReady} label={copy.scanLog.exportCodex} title={copy.scanLog.exportCodex} onClick={exportCodexRemediation} size="compact">
            <Sparkles size={14} />
          </IconButton>
        </div>

        <StructuredList
          title={copy.scanLog.timeline}
          items={steps.map((step) => ({
            id: step.stepId,
            title: step.checkId,
            leading: <RagBadge status={statusRag(step.status)} label={statusDisplayLabel(step.status, locale)} />,
            badges: step.findingCount ? <Badge tone="danger">{copy.execution.findingsCount(step.findingCount)}</Badge> : <Badge tone="good">{copy.execution.noFindings}</Badge>,
            meta: step.evidenceFile ?? step.message ?? copy.execution.noEvidenceFile
          }))}
          emptyLabel={copy.scanLog.noSteps}
          ariaLabel={copy.scanLog.timeline}
          className="security-list-card"
        />

        <div className="security-split-grid">
          <StructuredList
            title={copy.scanLog.evidenceFiles}
            items={evidenceFiles.map((file) => ({
              id: file,
              title: file,
              leading: file.endsWith(".md") ? <ScrollText size={15} /> : <FileJson size={15} />,
              badges: <Badge tone={file === "central-result-envelope.json" ? "info" : "good"}>{file.endsWith(".json") ? "json" : "markdown"}</Badge>,
              meta: copy.execution.reportsPathEvidence
            }))}
            emptyLabel={copy.scanLog.noFiles}
            ariaLabel={copy.scanLog.evidenceFiles}
            className="security-list-card"
          />
          <StructuredList
            title={copy.scanLog.blockers}
            items={blockingReasons.map((reason, index) => ({
              id: `blocker-${index}`,
              title: reason,
              leading: <AlertTriangle size={15} />,
              badges: <Badge tone="danger">{translateStatus(locale, "blocked")}</Badge>
            }))}
            emptyLabel={copy.scanLog.noBlockers}
            ariaLabel={copy.scanLog.blockers}
            className="security-list-card"
          />
        </div>

        <StructuredList
          title={copy.scanLog.findings}
          items={findings.slice(0, 12).map((finding) => ({
            id: finding.id,
            title: finding.title,
            leading: <FileWarning size={15} />,
            badges: (
              <span className="security-inline-badges">
                <Badge tone={statusTone(finding.severity)}>{finding.severity.toUpperCase()}</Badge>
                <Badge tone={finding.scope === "platform" ? "warning" : "info"}>{findingScopeLabel(finding, locale)}</Badge>
                <Badge tone={finding.triageStatus === "fixed" || finding.triageStatus === "false-positive" ? "good" : finding.triageStatus === "open" ? "danger" : "warning"}>
                  {copy.scanLog.triageLabel(finding.triageStatus)}
                </Badge>
              </span>
            ),
            meta: `${finding.tool} · ${findingLocation(finding, copy.scanLog.noLocation)} · ${finding.recommendation}`,
            actions: (
              <span className="security-hover-actions">
                <IconButton
                  disabled={triagingFindingId === finding.id || !authReady}
                  label={copy.scanLog.markOpen}
                  size="compact"
                  title={copy.scanLog.markOpen}
                  onClick={() => updateFindingTriageState(finding.id, "open")}
                >
                  <AlertTriangle size={13} />
                </IconButton>
                <IconButton
                  disabled={triagingFindingId === finding.id || !authReady}
                  label={copy.scanLog.markAccepted}
                  size="compact"
                  title={copy.scanLog.markAccepted}
                  onClick={() => updateFindingTriageState(finding.id, "accepted")}
                >
                  <Archive size={13} />
                </IconButton>
                <IconButton
                  disabled={triagingFindingId === finding.id || !authReady}
                  label={copy.scanLog.markFixed}
                  size="compact"
                  title={copy.scanLog.markFixed}
                  onClick={() => updateFindingTriageState(finding.id, "fixed")}
                >
                  <CheckCircle2 size={13} />
                </IconButton>
              </span>
            )
          }))}
          emptyLabel={copy.scanLog.noFindings}
          ariaLabel={copy.scanLog.findings}
          className="security-list-card"
        />
      </div>
    );
  }

  function renderTelemetry() {
    return (
      <div className="security-view-stack">
        <section className="security-analysis-panel">
          <div>
            <h2>{copy.telemetry.title}</h2>
            <p>{copy.telemetry.body}</p>
          </div>
          <Badge tone="warning">{copy.telemetry.integrationPartial}</Badge>
        </section>
        <StructuredList
          title={copy.telemetry.centralEnvelope}
          description={copy.telemetry.centralEnvelopeDescription}
          count={<Badge tone="info">OpenAPI v1</Badge>}
          items={[
            {
              id: "endpoint",
              title: "POST /api/v1/results/ingest",
              leading: <Database size={15} />,
              badges: <Badge tone="good">{translateStatus(locale, "implemented")}</Badge>,
              meta: copy.telemetry.endpointImplemented
            },
            {
              id: "redaction",
              title: copy.telemetry.redactedEnvelope,
              leading: <FileJson size={15} />,
              badges: <Badge tone="good">{translateStatus(locale, "implemented")}</Badge>,
              meta: copy.telemetry.noRawSource
            },
            {
              id: "delivery",
              title: copy.telemetry.deliveryStatus,
              leading: <History size={15} />,
              badges: <Badge tone="warning">{translateStatus(locale, "missing")}</Badge>,
              meta: copy.telemetry.centralEvidenceNeeded
            },
            {
              id: "auth",
              title: copy.telemetry.authenticatedIntake,
              leading: <ShieldCheck size={15} />,
              badges: <Badge tone={authStatus?.required ? "good" : "warning"}>{authStatus?.mode ?? translateStatus(locale, "unknown")}</Badge>,
              meta: authStatus?.configured ? copy.telemetry.protectedBoundary : copy.telemetry.authConfigIncomplete
            }
          ]}
          ariaLabel={copy.telemetry.centralTelemetryAria}
          className="security-list-card"
        />
        <StructuredList
          title={copy.telemetry.accessControl}
          description={copy.telemetry.accessDescription}
          count={<Badge tone={authReady ? "good" : authStatus?.required ? "danger" : "warning"}>{authLabel}</Badge>}
          toolbar={
            <span className="security-toolbar-actions">
              {oidcClient ? (
                <Button disabled={Boolean(authToken)} onClick={signInWithOidc} size="compact">
                  <LogIn size={14} />
                  {copy.telemetry.signIn}
                </Button>
              ) : null}
              {authToken ? (
                <Button onClick={signOut} size="compact">
                  <LogOut size={14} />
                  {copy.telemetry.signOut}
                </Button>
              ) : null}
            </span>
          }
          items={[
            {
              id: "mode",
              title: copy.telemetry.apiAuthMode,
              leading: <ShieldCheck size={15} />,
              badges: <Badge tone={authStatus?.configured ? "good" : "danger"}>{authStatus?.mode ?? translateStatus(locale, "unknown")}</Badge>,
              meta: authStatus?.issuer ?? copy.telemetry.sharedTokenOrLocal
            },
            {
              id: "roles",
              title: copy.telemetry.rbacRoles,
              leading: <FileJson size={15} />,
              badges: <Badge tone="info">{copy.telemetry.operatorRoles(authStatus?.operatorRoles.length ?? 0)}</Badge>,
              meta: authStatus?.operatorRoles.join(", ") || copy.telemetry.notLoaded
            },
            {
              id: "cors",
              title: copy.telemetry.browserBoundary,
              leading: <Archive size={15} />,
              badges: <Badge tone="good">{copy.telemetry.corsAllowlist}</Badge>,
              meta: apiBaseUrl
            }
          ]}
          ariaLabel={copy.telemetry.accessAria}
          className="security-list-card"
        />
        {authStatus?.required && !authToken ? (
          <DataGridShell title={<strong>{copy.telemetry.bearerSession}</strong>} className="security-grid-shell">
            <div className="security-auth-panel">
              <label className="security-akb-question">
                <span>{copy.telemetry.bearerToken}</span>
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
                  {copy.telemetry.useToken}
                </Button>
                {oidcClient ? (
                  <Button onClick={signInWithOidc}>
                    <LogIn size={14} />
                    STRATOS OIDC
                  </Button>
                ) : null}
              </div>
              <div className="security-result" data-tone={authStatus.configured ? "warning" : "danger"} role="status">
                <strong>{authStatus.configured ? copy.telemetry.protectedApi : copy.telemetry.authConfigIncomplete}</strong>
                <p>{authMessage}</p>
              </div>
            </div>
          </DataGridShell>
        ) : null}
        <div className="security-split-grid">
          <StructuredList
            title={copy.telemetry.akbIntegration}
            description={copy.telemetry.akbDescription}
            count={
              <Badge tone={akbStatus?.configured ? "good" : "warning"}>
                {akbStatus?.configured ? translateStatus(locale, "configured") : translateStatus(locale, "not configured")}
              </Badge>
            }
            toolbar={
              <Button onClick={refreshAkbStatus} size="compact">
                <Bot size={14} />
                {copy.dashboard.refresh}
              </Button>
            }
            items={[
              {
                id: "rag",
                title: copy.telemetry.akbRagEndpoint,
                leading: <MessageSquareText size={15} />,
                badges: <Badge tone={akbStatus?.ragConfigured ? "good" : "warning"}>{akbStatus?.ragConfigured ? translateStatus(locale, "ready") : translateStatus(locale, "missing")}</Badge>,
                meta: akbStatus?.publicBaseUrl ?? copy.telemetry.setAkbBaseUrl
              },
              {
                id: "auth",
                title: copy.telemetry.authenticationMode,
                leading: <ShieldCheck size={15} />,
                badges: <Badge tone={akbStatus?.authMode === "none" ? "warning" : "good"}>{akbStatus?.authMode ?? translateStatus(locale, "unknown")}</Badge>,
                meta: copy.telemetry.authModeMeta
              },
              {
                id: "boundaries",
                title: copy.telemetry.storageBoundary,
                leading: <Archive size={15} />,
                badges: <Badge tone="good">{copy.telemetry.noLocalAiStorage}</Badge>,
                meta: copy.telemetry.storageMeta
              },
              {
                id: "citations",
                title: copy.telemetry.citationsRequired,
                leading: <FileJson size={15} />,
                badges: <Badge tone="good">require_citations</Badge>,
                meta: copy.telemetry.noAnswerMachineReadable
              }
            ]}
            ariaLabel={copy.telemetry.akbAria}
            className="security-list-card"
          />

          <DataGridShell
            title={<strong>{copy.telemetry.askAkbTitle}</strong>}
            toolbar={<Badge tone={akbStatus?.configured ? "good" : "warning"}>{latestRun?.id ?? copy.telemetry.noScan}</Badge>}
            className="security-grid-shell"
          >
            <div className="security-akb-panel">
              <label className="security-akb-question">
                <span>{copy.telemetry.question}</span>
                <textarea
                  value={akbQuestion}
                  onChange={(event) => setAkbQuestion(event.currentTarget.value)}
                  rows={4}
                />
              </label>
              <div className="security-actions">
                <Button variant="primary" disabled={!latestRun || akbLoading || !authReady} onClick={askAkb}>
                  <Sparkles size={14} />
                  {akbLoading ? copy.telemetry.askingAkb : copy.telemetry.askAkb}
                </Button>
                <Button disabled={akbLoading} onClick={() => setAkbQuestion(copy.telemetry.auditPromptText)}>
                  <MessageSquareText size={14} />
                  {copy.telemetry.auditPrompt}
                </Button>
              </div>
              <div className="security-result" data-tone={akbAnswer ? "good" : akbStatus?.configured ? "warning" : "danger"} role="status">
                <strong>{akbAnswer ? copy.telemetry.akbResponse : copy.telemetry.akbStatus}</strong>
                <p>{akbAnswer?.answer ?? akbMessage}</p>
                {akbAnswer?.confidence != null ? <span>{copy.telemetry.confidence} {Math.round(akbAnswer.confidence * 100)}%</span> : null}
              </div>
              {akbAnswer?.citations.length ? (
                <StructuredList
                  title={copy.telemetry.citations}
                  items={akbAnswer.citations.map((citation, index) => ({
                    id: citation.chunkId ?? `citation-${index}`,
                    title: citation.title ?? citation.documentId ?? copy.telemetry.akbCitation,
                    leading: <FileJson size={15} />,
                    badges: <Badge tone="info">{citation.page ? copy.telemetry.page(citation.page) : translateStatus(locale, "source")}</Badge>,
                    meta: citation.sectionPath ?? citation.openUrl ?? citation.chunkId ?? copy.telemetry.citationContext
                  }))}
                  ariaLabel={copy.telemetry.citations}
                />
              ) : null}
            </div>
          </DataGridShell>
        </div>
      </div>
    );
  }

  const renderedView =
    activeView === "new-scan"
      ? renderNewScan()
      : activeView === "capabilities"
      ? renderCapabilities()
      : activeView === "execution"
        ? renderExecution()
        : activeView === "telemetry"
          ? renderTelemetry()
          : renderDashboard();

  const workspaceContextLabel = accessDenied
    ? copy.auth.accessDeniedTopbar
    : `SecurityPreflight / ${
        activeView === "new-scan"
          ? copy.views.newScan
          : activeView === "dashboard"
          ? copy.views.dashboard
          : activeView === "capabilities"
            ? copy.views.capabilities
            : activeView === "execution"
              ? copy.views.executionShort
              : copy.views.telemetryShort
      }`;

  function renderSettingsSurface() {
    return (
      <StratosSettingsSurface
        variant="modal"
        open={settingsOpen}
        locale={locale}
        values={settingsValues}
        userInitials="SA"
        appNavItems={settingsAppNavItems}
        appSections={settingsAppSections}
        themeOptions={settingsThemeOptions}
        accentOptions={settingsAccentOptions}
        mode={settingsMode}
        activeItemId={settingsActiveItemId}
        dirty={settingsDirty}
        onActiveItemChange={setSettingsActiveItemId}
        onValueChange={handleSettingsCoreValueChange}
        onClose={() => setSettingsOpen(false)}
        onModeChange={setSettingsMode}
        onLogout={signOut}
        onSave={() => setSavedSettingsDraft(settingsDraft)}
      />
    );
  }

  function renderGlobalTopbar() {
    return (
      <GlobalTopbar
        apps={stratosTopbarApps}
        className="security-global-topbar"
        labels={{ applications: copy.topbar.applications, userMenu: copy.topbar.userMenu, settings: copy.topbar.settings, logout: copy.topbar.logout }}
        context={<span>{workspaceContextLabel}</span>}
        center={<span className="security-topbar-spacer" aria-hidden="true" />}
        status={accessDenied ? <Badge tone="danger">{copy.auth.accessDenied}</Badge> : <RagBadge status={statusRag(scanGate)} label={statusDisplayLabel(scanGate, locale)} />}
        onSettings={() => setSettingsOpen(true)}
        onLogout={signOut}
        actions={
          <div className="security-topbar-actions">
            <div className="security-language-switch" aria-label={copy.language}>
              <button
                type="button"
                className={locale === "cs" ? "is-active" : undefined}
                onClick={() => changeLocale("cs")}
                aria-pressed={locale === "cs"}
                title={copy.languageCzech}
              >
                CS
              </button>
              <button
                type="button"
                className={locale === "en" ? "is-active" : undefined}
                onClick={() => changeLocale("en")}
                aria-pressed={locale === "en"}
                title={copy.languageEnglish}
              >
                EN
              </button>
            </div>
            {accessDenied ? (
              authToken ? (
                <Button onClick={signOut} size="compact">
                  <LogOut size={14} />
                  {copy.topbar.logout}
                </Button>
              ) : authStatus?.required ? (
                <Button disabled={!oidcClient} onClick={signInWithOidc} size="compact">
                  <LogIn size={14} />
                  {copy.telemetry.signIn}
                </Button>
              ) : null
            ) : (
              <>
                <Button disabled={loadingDoctor || !authReady} onClick={refreshDoctor} size="compact">
                  <Wrench size={14} />
                  {loadingDoctor ? copy.topbar.checking : copy.topbar.doctor}
                </Button>
                {authStatus?.required && !authToken ? (
                  <Button disabled={!oidcClient} onClick={signInWithOidc} size="compact">
                    <LogIn size={14} />
                    {copy.telemetry.signIn}
                  </Button>
                ) : null}
              </>
            )}
          </div>
        }
        user={{ name: copy.topbar.userName, initials: "SA", status: authLabel }}
      />
    );
  }

  if (accessDenied) {
    return (
      <AppShell
        className="security-shell security-shell-access-denied"
        sidebarOpen={false}
        onSidebarChange={setSidebarOpen}
        topbarPlacement="global"
        topbar={renderGlobalTopbar()}
      >
        <main className="security-access-denied" aria-label={copy.auth.accessDeniedAria}>
          <section className="security-access-denied-scene">
            <div className="security-access-visual" aria-hidden="true">
              <div className="security-access-grid" />
              <div className="security-access-shield">
                <ShieldCheck size={54} aria-hidden="true" />
                <span>SP</span>
              </div>
              <div className="security-access-lockline">
                <span />
                <span />
                <span />
              </div>
            </div>
            <div className="security-access-copy">
              <Badge tone="danger">{copy.auth.accessDenied}</Badge>
              <ErrorState
                title={copy.auth.accessDeniedTitle}
                error={null}
                fallbackMessage={copy.auth.accessDeniedBody}
                className="security-access-error-state"
              />
              <p>{copy.auth.accessDeniedHint}</p>
            </div>
          </section>
        </main>
        {renderSettingsSurface()}
      </AppShell>
    );
  }

  return (
    <AppShell
      className="security-shell"
      sidebarOpen={sidebarOpen}
      onSidebarChange={setSidebarOpen}
      topbarPlacement="global"
      rail={
        <AppRail
          workspaceMark="SP"
          items={[
            { id: "security", label: copy.views.security, icon: ShieldCheck },
            { id: "evidence", label: copy.views.evidence, icon: Archive }
          ]}
          footerItems={[{ id: "settings", label: copy.topbar.settings, icon: Settings }]}
          activeItemId={activeRailPanel}
          panelOpen={sidebarOpen}
          onItemSelect={handleRailItemSelect}
        />
      }
      sidebar={
        <WorkspaceSidebar
          title="SecurityPreflight"
          subtitle={copy.sidebar.subtitle}
          showHeader={false}
          className="security-workspace-sidebar"
          footer={
            <div className="security-sidebar-footer">
              <Badge tone="good">{copy.sidebar.localOnly}</Badge>
              <span>API {apiBaseUrl.replace("http://", "")}</span>
            </div>
          }
        >
          <header className="security-workspace-header">
            <div>
              <h1>SecurityPreflight</h1>
              <p>{copy.sidebar.subtitle}</p>
            </div>
            <div className="security-sidebar-hover-actions" aria-label={copy.sidebar.headerActions}>
              <button
                type="button"
                className="security-sidebar-icon-button"
                title={copy.sidebar.collapseSubmenus}
                aria-label={copy.sidebar.collapseSubmenus}
                onClick={() => setSidebarOpen(false)}
              >
                <ChevronsLeft size={16} aria-hidden="true" />
              </button>
            </div>
          </header>
          {renderSidebarNav()}
        </WorkspaceSidebar>
      }
      topbar={renderGlobalTopbar()}
    >
      <div className="security-content">
        <section className="security-main">{renderedView}</section>
      </div>

      <DetailSurface
        open={detailOpen}
        mode={detailMode}
        title={copy.detail.title}
        labels={{ close: copy.detail.close, sidebar: copy.detail.sidebar, modal: copy.detail.modal, fullscreen: copy.detail.fullscreen }}
        onClose={() => setDetailOpen(false)}
        onModeChange={setDetailMode}
      >
        <div className="security-detail-stack">
          <section>
            <h2>{copy.detail.currentAssessment}</h2>
            <p>{copy.detail.body}</p>
          </section>
          <section className="security-blocker-panel" aria-label={copy.detail.p0Blockers}>
            <h2>{copy.detail.p0Blockers}</h2>
            <div className="security-blocker-list" role="list">
              {criticalCapabilityRows.map((row) => (
                <article key={row.id} className="security-blocker-row" role="listitem">
                  <div className="security-blocker-row-header">
                    <RagBadge status={statusRag(row.status)} label={statusDisplayLabel(row.status, locale)} />
                    <strong>{row.area}</strong>
                    <span>{row.priority}</span>
                  </div>
                  <p>{row.gap}</p>
                </article>
              ))}
              {criticalCapabilityRows.length === 0 ? (
                <p className="security-blocker-empty">{copy.scanLog.noBlockers}</p>
              ) : null}
            </div>
          </section>
        </div>
      </DetailSurface>
      <DetailSurface
        open={scanLogOpen}
        mode={scanLogMode}
        title={copy.scanLog.title}
        labels={{ close: copy.detail.close, sidebar: copy.detail.sidebar, modal: copy.detail.modal, fullscreen: copy.detail.fullscreen }}
        onClose={() => setScanLogOpen(false)}
        onModeChange={setScanLogMode}
      >
        {renderScanLogSurface()}
      </DetailSurface>
      <CommandCenter
        open={commandOpen}
        query={commandQuery}
        items={commandItems}
        labels={{
          title: copy.command.title,
          placeholder: copy.command.placeholder,
          noResults: copy.command.noResults,
          open: copy.command.open,
          close: copy.command.close,
          actions: copy.command.actions,
          preview: copy.command.preview
        }}
        onQueryChange={setCommandQuery}
        onClose={() => setCommandOpen(false)}
      />
      {renderSettingsSurface()}
    </AppShell>
  );
}
