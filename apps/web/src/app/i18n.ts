export type AppLocale = "cs" | "en";
export type CapabilityStatus = "Ready" | "Partial" | "Gap" | "Blocked";

export interface ProjectRow {
  id: string;
  name: string;
  path: string;
  stack: string;
  data: string;
  gate: string;
  findings: string;
}

export interface CapabilityRow {
  id: string;
  area: string;
  status: CapabilityStatus;
  implemented: string;
  gap: string;
  priority: string;
}

export interface ExecutionStage {
  id: string;
  title: string;
  meta: string;
  status: CapabilityStatus;
}

export const localeStorageKey = "security-preflight.locale";
export const defaultLocale: AppLocale = "cs";

export const localizedProjectRows: Record<AppLocale, ProjectRow[]> = {
  cs: [
    {
      id: "security-preflight",
      name: "SecurityPreflight",
      path: "/workspace/projects",
      stack: "Next.js / Fastify / Worker",
      data: "interní",
      gate: "READY",
      findings: "0 vysokých / 0 středních"
    },
    {
      id: "hospital-api",
      name: "Hospital API",
      path: "~/Projects/hospital-api",
      stack: "Node.js / OpenAPI",
      data: "zdravotní data",
      gate: "FAIL",
      findings: "2 vysoké / 5 středních"
    },
    {
      id: "claims-portal",
      name: "Claims Portal",
      path: "~/Projects/claims-portal",
      stack: "Next.js / Docker",
      data: "citlivé",
      gate: "WARNING",
      findings: "0 vysokých / 3 střední"
    }
  ],
  en: [
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
  ]
};

export const localizedFallbackTools: Record<AppLocale, Array<{ name: string; status: string; version: string }>> = {
  cs: [
    { name: "Docker Desktop", status: "available", version: "compose runtime" },
    { name: "Gitleaks", status: "container", version: "worker/toolbox" },
    { name: "Semgrep", status: "container", version: "worker/toolbox" },
    { name: "Trivy", status: "container", version: "worker/toolbox" },
    { name: "Syft / Grype / OSV", status: "container", version: "worker/toolbox" },
    { name: "Checkov IaC", status: "container", version: "worker/toolbox" },
    { name: "Centrální výsledkové API", status: "available", version: "obálka v1" }
  ],
  en: [
    { name: "Docker Desktop", status: "available", version: "compose runtime" },
    { name: "Gitleaks", status: "container", version: "worker/toolbox" },
    { name: "Semgrep", status: "container", version: "worker/toolbox" },
    { name: "Trivy", status: "container", version: "worker/toolbox" },
    { name: "Syft / Grype / OSV", status: "container", version: "worker/toolbox" },
    { name: "Checkov IaC", status: "container", version: "worker/toolbox" },
    { name: "Central results API", status: "available", version: "v1 envelope" }
  ]
};

export const localizedCapabilityRows: Record<AppLocale, CapabilityRow[]> = {
  cs: [
    {
      id: "scan-planning",
      area: "Plánování skenů a guardraily",
      status: "Ready",
      implemented: "Profily, dry-run plánování, blokování aktivního DAST a cesty k evidenci příkazů.",
      gap: "Doplnit projektové policy override a výběr profilů podle diffu.",
      priority: "P1"
    },
    {
      id: "worker-execution",
      area: "Spouštění workerem",
      status: "Partial",
      implemented: "Queue endpoint, worker consumer, interní kontroly, runner externích scannerů a UI log běhu nad reportovou evidencí.",
      gap: "Chybí serverový live progress stream, rušení běhů a retry fronta.",
      priority: "P0"
    },
    {
      id: "healthcare-reference",
      area: "Referenční zdravotnické kontroly",
      status: "Partial",
      implemented: "Přísný profil, fail-closed evidence scannerů, Greenbone/OpenSCAP import, DefectDojo SARIF a redakce centrální obálky.",
      gap: "Chybí katalog policy, retenční matice, ověření řízení přístupu a kontroly audit-logů.",
      priority: "P0"
    },
    {
      id: "findings",
      area: "Správa nálezů",
      status: "Gap",
      implemented: "Normalizovaný model nálezů a reportové výstupy existují v balíčcích.",
      gap: "Chybí UI pro triage, výjimky, vlastníky, SLA nápravy a drill-down evidence.",
      priority: "P0"
    },
    {
      id: "reports",
      area: "Reporty a evidence",
      status: "Ready",
      implemented: "Markdown, JSON, SARIF, execution-result, centrální obálka, delivery manifesty, prohlížeč evidence a PDF/PPTX export.",
      gap: "Doplnit retenční řízení evidence.",
      priority: "P1"
    },
    {
      id: "akb-ai",
      area: "STRATOS AKB AI bridge",
      status: "Partial",
      implemented: "Serverový AKB RAG bridge s citovanými odpověďmi, bez lokálního ukládání promptů, odpovědí a chunků.",
      gap: "Chybí produkční AKB URL/OIDC konfigurace a kontraktové testy proti živému AKB OpenAPI.",
      priority: "P0"
    },
    {
      id: "telemetry",
      area: "Centrální telemetrie",
      status: "Partial",
      implemented: "OpenAPI ingest endpoint, volitelný worker delivery, redigovaná výsledková obálka a manifesty doručení.",
      gap: "Chybí retry buffer, centrální stavová timeline a produkční konfigurace sinku.",
      priority: "P1"
    },
    {
      id: "projects",
      area: "Registr projektů",
      status: "Partial",
      implemented: "API a dashboard podporují perzistentní registraci projektů, validaci cest pod PROJECTS_ROOT_CONTAINER a detekci stacku.",
      gap: "Chybí plná editační obrazovka, projektové policy overrides a detailní nastavení profilu.",
      priority: "P0"
    },
    {
      id: "auth",
      area: "Autentizace a autorizace",
      status: "Partial",
      implemented: "API podporuje STRATOS OIDC/JWKS RBAC, přechodový shared-token režim, chráněné endpointy a předání bearer tokenu z UI.",
      gap: "Produkce ještě vyžaduje Keycloak klienta/role, TLS terminaci a perzistenci auditních událostí.",
      priority: "P0"
    }
  ],
  en: [
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
      implemented: "Queue endpoint, worker consumer, internal checks, external scanner runner, and run log UI over report evidence.",
      gap: "No server-side live progress stream, cancellation, or retry queue yet.",
      priority: "P0"
    },
    {
      id: "healthcare-reference",
      area: "Healthcare reference checks",
      status: "Partial",
      implemented: "Strict profile, fail-closed scanner evidence, Greenbone/OpenSCAP import, DefectDojo SARIF, and central envelope redaction.",
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
      implemented: "Markdown, JSON, SARIF, execution-result, central envelope, delivery manifests, evidence browser, and PDF/PPTX export workflow.",
      gap: "Add evidence retention controls.",
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
      implemented: "OpenAPI ingest endpoint, optional worker delivery, redacted result envelope, and delivery manifests.",
      gap: "Needs retry buffer, central delivery timeline, and production sink configuration.",
      priority: "P1"
    },
    {
      id: "projects",
      area: "Project registry",
      status: "Partial",
      implemented: "API and dashboard support persistent project registration, PROJECTS_ROOT_CONTAINER path validation, and stack detection.",
      gap: "Needs a full edit surface, per-project policy overrides, and detailed profile settings.",
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
  ]
};

export const localizedExecutionStages: Record<AppLocale, ExecutionStage[]> = {
  cs: [
    { id: "intake", title: "Příjem projektu", meta: "pevný Docker workspace mount", status: "Partial" },
    { id: "plan", title: "Plán", meta: "profilové kontroly, guardraily, cesty evidence", status: "Ready" },
    { id: "queue", title: "Fronta", meta: "Redis-backed požadavek na sken", status: "Ready" },
    { id: "run", title: "Běh", meta: "spuštění worker/toolbox", status: "Partial" },
    { id: "triage", title: "Triage", meta: "UI nálezů a výjimky", status: "Gap" },
    { id: "export", title: "Export", meta: "reporty a centrální obálka", status: "Partial" }
  ],
  en: [
    { id: "intake", title: "Project intake", meta: "fixed Docker workspace mount", status: "Partial" },
    { id: "plan", title: "Plan", meta: "profile checks, guardrails, evidence paths", status: "Ready" },
    { id: "queue", title: "Queue", meta: "Redis-backed scan request", status: "Ready" },
    { id: "run", title: "Run", meta: "worker/toolbox execution", status: "Partial" },
    { id: "triage", title: "Triage", meta: "findings UI and exceptions", status: "Gap" },
    { id: "export", title: "Export", meta: "reports and central envelope", status: "Partial" }
  ]
};

export const uiText = {
  cs: {
    language: "Jazyk",
    languageCzech: "Čeština",
    languageEnglish: "Angličtina",
    topbar: {
      applications: "Aplikace STRATOS",
      userMenu: "Uživatelské menu",
      settings: "Nastavení",
      logout: "Odhlásit",
      commandCenter: "Příkazové centrum",
      doctor: "Doctor",
      checking: "Kontroluji",
      audit: "Audit",
      userName: "Bezpečnostní analytik"
    },
    views: {
      workspace: "Pracovní prostor",
      dashboard: "Dashboard",
      capabilities: "Audit schopností",
      execution: "Spuštění a evidence",
      executionShort: "Spuštění",
      telemetry: "Telemetrie a AKB",
      telemetryShort: "Telemetrie",
      backlog: "Backlog obrazovek",
      findings: "Triage nálezů",
      reportsExports: "Reporty a exporty",
      security: "Bezpečnost",
      evidence: "Evidence"
    },
    disabledReasons: {
      findings: "Vyžaduje perzistentní UI nálezů a workflow výjimek.",
      settings: "Nastavení je v backlogu."
    },
    statusLabels: {
      Ready: "Připraveno",
      Partial: "Částečně",
      Gap: "Mezera",
      Blocked: "Blokováno",
      READY: "PŘIPRAVENO",
      PASS: "PROŠLO",
      WARNING: "VAROVÁNÍ",
      FAIL: "SELHÁNÍ",
      ERROR: "CHYBA",
      idle: "čeká",
      loading: "pracuje",
      success: "připraveno",
      error: "chyba",
      available: "dostupné",
      container: "kontejner",
      optional: "volitelné",
      completed: "dokončeno",
      queued: "ve frontě",
      running: "běží",
      failed: "selhalo",
      missing: "chybí",
      blocked: "blokováno",
      ready: "připraveno",
      live: "živě",
      fallback: "fallback",
      configured: "nastaveno",
      "not configured": "nenastaveno",
      implemented: "hotovo",
      planned: "plánováno",
      empty: "prázdné",
      unknown: "neznámé",
      source: "zdroj"
    },
    scanProfiles: {
      "fast-local": {
        name: "Rychlá lokální kontrola",
        description: "Rychlá lokální zpětná vazba pro secrets, dokumentaci, OpenAPI, lehké SAST a filesystem SCA."
      },
      "pre-commit": {
        name: "Pre-commit brána",
        description: "Pre-commit kontrola pro secrets, lehké kontroly kódu, závislosti, OpenAPI a zakázané soubory."
      },
      "pre-release": {
        name: "Předrelease připravenost",
        description: "Release profil s plnými scannery, dokumentační shodou, vyhodnocením gate a reporty."
      },
      "api-security": {
        name: "Bezpečnost API",
        description: "OpenAPI JSON-first kontroly, ErrorResponse shoda, health/readiness endpointy a bezpečné runtime API sondy."
      },
      "web-perimeter-safe": {
        name: "Bezpečný web perimeter",
        description: "Bezpečné DNS, TLS, porty, HTTP hlavičky, endpoint discovery, WAF fingerprint a Nuclei safe-template kontroly pro povolený webový cíl."
      },
      "controlled-dast-local": {
        name: "Řízený lokální DAST",
        description: "Řízený OWASP ZAP baseline profil pro localhost nebo výslovně povolené staging cíle vlastněné uživatelem."
      },
      "openapi-runtime-safe": {
        name: "Bezpečný OpenAPI runtime",
        description: "OpenAPI kontrakt, bezpečné GET/HEAD runtime sondy a ZAP API scan pro výslovně povolený API cíl."
      },
      "external-vps-safe": {
        name: "Externí VPS safe scan",
        description: "Profil pro hardened externí scanner VPS se ZAP baseline, Nuclei safe templates a podepsaným návratem výsledků."
      },
      "enterprise-assurance": {
        name: "Enterprise assurance",
        description: "Profil pro zdravotnické evidence pipeline s Greenbone/OpenVAS importem, OpenSCAP importem/evaluací, DefectDojo SARIF exportem a lokální SBOM/IaC evidencí."
      },
      "container-security": {
        name: "Bezpečnost kontejnerů",
        description: "Kontroly Dockerfile, image a kontejnerových misconfigurací."
      },
      "documentation-compliance": {
        name: "Dokumentační shoda",
        description: "Kontroly povinné repozitářové dokumentace a minimálního obsahu."
      },
      "sensitive-data-ready": {
        name: "Připravenost citlivých dat",
        description: "Přísné kontroly připravenosti pro zdravotnické, nemocniční a vysoce citlivé systémy."
      },
      "healthcare-reference": {
        name: "Zdravotnický referenční profil",
        description: "Referenční profil pro zdravotnické a vysoce citlivé systémy vyžadující evidenci, privacy, SBOM, API, IaC a centrální export výsledků."
      }
    },
    columns: {
      project: "Projekt",
      stack: "Stack",
      data: "Data",
      gate: "Gate",
      open: "Otevřené",
      profile: "Profil",
      status: "Stav",
      result: "Výsledek",
      findings: "Nálezy",
      finished: "Dokončeno",
      capability: "Schopnost",
      implemented: "Hotovo",
      gap: "Mezera",
      owner: "Vlastník",
      updated: "Aktualizováno"
    },
    dashboard: {
      maturityAria: "Souhrn zralosti SecurityPreflight",
      functionalMaturity: "Funkční zralost",
      maturityDetail: (criticalGaps: number) => `${criticalGaps} P0 mezer zbývá před referenčním zdravotnickým použitím.`,
      scanProfiles: "Scan profily",
      scanProfilesDetail: "Načteno z lokálního API kontraktu.",
      toolchain: "Toolchain",
      notChecked: "nezkontrolováno",
      toolchainDetail: (missing: number, error: number, optionalGap: boolean) =>
        `${missing} zdravotnických chybí / ${error} chyba${optionalGap ? " / volitelná DAST mezera" : ""}`,
      doctorDetail: "Spusťte doctor pro ověření dostupnosti scannerů.",
      reports: "Reporty",
      reportsDetail: "STRATOS redigované exporty plus centrální obálka v1.",
      projects: "Projekty",
      registryPending: "registr UI čeká",
      noProjects: "Žádné projekty",
      registeredProjects: "Registrované projekty",
      loadingProjects: "Načítám projekty",
      recentScans: "Poslední běhy skenů",
      refreshing: "Obnovuji",
      refresh: "Obnovit",
      noCompletedEvidence: "Zatím žádná dokončená evidence skenu",
      recentScansAria: "Poslední skeny",
      toolchainDoctor: "Toolchain doctor",
      dockerScannerStack: "Docker scanner stack",
      checked: "Zkontrolováno",
      check: "Zkontrolovat",
      toolVersionFallback: "nenahlášeno"
    },
    projects: {
      registrationTitle: "Registrace projektu",
      name: "Název",
      path: "Cesta v kontejneru",
      owner: "Vlastník",
      dataClassification: "Klasifikace dat",
      repositoryUrl: "Repository URL",
      register: "Registrovat projekt",
      registering: "Registruji",
      refresh: "Obnovit projekty",
      selectProject: "Vybraný projekt",
      noSelectedProject: "Bez registrovaného projektu",
      stackUnknown: "nezjištěno",
      projectRegistered: (name: string) => `Projekt ${name} byl zaregistrován.`,
      registrationFailed: "Registrace projektu selhala.",
      loadFailed: "Nepodařilo se načíst projekty.",
      authRequired: "Před správou projektů je vyžadována autentizace.",
      pathHelp: "Zadejte absolutní cestu v kontejneru uvnitř PROJECTS_ROOT_CONTAINER, např. /workspace/projects/moje-aplikace.",
      classifications: {
        public: "veřejná",
        internal: "interní",
        confidential: "důvěrná",
        sensitive: "citlivá",
        "health-data": "zdravotní data"
      }
    },
    capabilities: {
      title: "Celková funkčnost",
      body: "Aplikace má funkční lokální scan pipeline, OpenAPI kontrakt, worker evidence, log běhu, report exporty a AKB bridge podle STRATOS hranic. Největší mezery zůstávají triage findings, serverový live progress stream, produkční AKB/OIDC konfigurace a bezpečnostní hranice pro sdílené nasazení.",
      maturityEstimate: "Odhad zralosti",
      maturityProgress: "Funkční zralost",
      auditTitle: "Audit schopností",
      p0Gaps: (criticalGaps: number) => `${criticalGaps} P0 mezer`,
      noMatching: "Žádné odpovídající schopnosti",
      aria: "Audit schopností"
    },
    execution: {
      lifecycle: "Životní cyklus spuštění",
      lifecycleDescription: "Aktuální end-to-end schopnost od lokálního projektu k evidenci",
      triageIncomplete: "triage nedokončena",
      plannedChecks: "Plánované kontroly vybraného profilu",
      planned: "plánováno",
      loadProfile: "Načtěte scan profil pro zobrazení plánovaných kontrol.",
      selectedChecks: "Kontroly vybraného scan profilu",
      latestEvidence: "Evidence posledního reportu",
      runScanForEvidence: "Spusťte sken pro vytvoření reportové evidence",
      refresh: "Obnovit",
      exportPdfLabel: "Exportovat poslední report jako PDF",
      exportPdfTitle: "Export redigovaného PDF reportu",
      exportPptxLabel: "Exportovat poslední report jako PPTX",
      exportPptxTitle: "Export redigovaného PPTX reportu",
      exportFilePdf: (file: string) => `Exportovat report ${file} jako PDF`,
      exportFilePptx: (file: string) => `Exportovat report ${file} jako PPTX`,
      exportScanPdf: "Export skenu jako PDF",
      exportScanPptx: "Export skenu jako PPTX",
      reportsPathEvidence: "REPORTS_PATH evidence",
      noEvidenceFiles: "Nenalezeny žádné soubory evidence",
      latestEvidenceAria: "Evidence posledního reportu",
      latestSteps: "Kroky posledního běhu",
      stepDetailDescription: (findings: number, finished: string) => `${findings} nálezů · dokončeno ${finished}`,
      selectScanForDetail: "Vyberte nebo spusťte sken pro načtení detailu kroků",
      notLoaded: "nenačteno",
      findingsCount: (count: number) => `${count} nálezů`,
      noFindings: "0 nálezů",
      noEvidenceFile: "bez souboru evidence",
      noStepDetail: "Žádný detail kroků není načten",
      latestStepsAria: "Kroky posledního běhu",
      reportExports: "Exporty reportů",
      exporting: (format: string) => `Exportuji ${format}`
    },
    telemetry: {
      title: "Telemetrie a centrální ukládání",
      body: "API nabízí v1 kontrakt centrálního ingestu, worker zapisuje redigovanou výsledkovou obálku a při explicitním zapnutí doručuje výsledky do centrálního sinku nebo DefectDojo.",
      integrationPartial: "doručení volitelné",
      centralEnvelope: "Centrální výsledková obálka",
      centralEnvelopeDescription: "Aktuální kontrakt a chybějící produkční kontroly",
      endpointImplemented: "contract-first ingest",
      redactedEnvelope: "Redigovaná worker obálka",
      noRawSource: "bez uploadu raw zdrojů",
      deliveryStatus: "Manifest doručení",
      centralEvidenceNeeded: "auditováno v report evidence",
      authenticatedIntake: "Autentizovaný centrální příjem",
      protectedBoundary: "chráněná API hranice dostupná",
      authConfigIncomplete: "konfigurace autentizace není kompletní",
      centralTelemetryAria: "Stav centrální telemetrie",
      accessControl: "Řízení přístupu",
      accessDescription: "STRATOS OIDC a produkční API hranice",
      signIn: "Přihlásit",
      signOut: "Odhlásit",
      apiAuthMode: "Režim autentizace API",
      sharedTokenOrLocal: "shared token nebo lokální vývoj",
      rbacRoles: "RBAC role",
      operatorRoles: (count: number) => `${count} operátorských rolí`,
      notLoaded: "nenačteno",
      browserBoundary: "Browser API hranice",
      corsAllowlist: "CORS allowlist",
      accessAria: "Stav řízení přístupu",
      bearerSession: "API bearer session",
      bearerToken: "Bearer token",
      useToken: "Použít token",
      protectedApi: "Chráněné API",
      akbIntegration: "AKB integrace",
      akbDescription: "Dokumentačně ukotvená AI hranice pro STRATOS",
      akbRagEndpoint: "AKB RAG endpoint",
      setAkbBaseUrl: "nastavte SECURITY_PREFLIGHT_AKB_RAG_BASE_URL",
      authenticationMode: "Režim autentizace",
      authModeMeta: "caller bearer, OIDC client credentials nebo service token",
      storageBoundary: "Hranice ukládání SecurityPreflight",
      noLocalAiStorage: "bez lokálního AI úložiště",
      storageMeta: "prompty, odpovědi, chunky a embeddingy zůstávají v AKB",
      citationsRequired: "Citace jsou povinné",
      noAnswerMachineReadable: "no-answer je strojově čitelné",
      akbAria: "Stav AKB integrace",
      askAkbTitle: "Zeptat se AKB na poslední sken",
      noScan: "bez skenu",
      question: "Otázka",
      askingAkb: "Ptám se AKB",
      askAkb: "Zeptat se AKB",
      auditPrompt: "Auditní prompt",
      auditPromptText: "Jaké jsou hlavní bezpečnostní závěry posledního skenu a jaká evidence je podporuje?",
      akbResponse: "AKB odpověď",
      akbStatus: "AKB stav",
      confidence: "jistota",
      citations: "Citace",
      akbCitation: "AKB citace",
      page: (page: number) => `strana ${page}`,
      citationContext: "kontext citace"
    },
    auth: {
      authenticated: "Přihlášeno",
      required: "Vyžaduje přihlášení",
      localMode: "Lokální režim",
      initial: "Stav autentizace zatím nebyl ověřen.",
      oidcEstablished: "STRATOS OIDC session byla navázána.",
      oidcFailed: "OIDC přihlášení selhalo.",
      apiRequired: "Pro přístup k API je vyžadována autentizace.",
      apiRequiredIncomplete: "Autentizace je vyžadována, ale není plně nakonfigurována.",
      localNoAuth: "Lokální vývojový režim nevyžaduje autentizaci API.",
      statusUnavailable: "Stav autentizace není dostupný.",
      tokenCleared: "Autentizační token byl vymazán.",
      oidcNotConfigured: "STRATOS OIDC klient není nakonfigurován."
    },
    messages: {
      exportInitial: "PDF/PPTX exporty používají pouze redigovanou reportovou evidenci.",
      akbInitial: "AKB odpovědi se v SecurityPreflight neukládají.",
      scanReady: "Připraveno spustit lokální sken přes Docker worker.",
      loadProfilesFailed: "Nepodařilo se načíst scan profily.",
      loadRunsFailed: "Nepodařilo se načíst historii běhů skenů.",
      loadEvidenceFailed: "Nepodařilo se načíst evidenci skenu.",
      scanFinished: (gate: string) => `Sken skončil s gate ${gate}.`,
      scanQueuedWaiting: "Scan job je ve frontě; čekám na worker evidenci.",
      scanQueuedNoEvidence: "Scan job byl zařazen do fronty, ale evidence zatím není dostupná.",
      authRequiredDoctor: "Před kontrolou toolchainu je vyžadována autentizace.",
      doctorFailed: "Toolchain doctor selhal.",
      akbStatusUnavailable: "AKB stav není dostupný.",
      authRequiredExport: "Před exportem reportů je vyžadována autentizace.",
      noScanEvidence: "Zatím není načtena žádná evidence skenu.",
      generatingExport: (format: string) => `Generuji ${format} export...`,
      exportGenerated: (format: string, fileName: string) => `${format} export vytvořen: ${fileName}`,
      exportFailed: (format: string) => `${format} export selhal.`,
      authRequiredAkb: "Před dotazem do AKB je vyžadována autentizace.",
      askingAkb: "Ptám se AKB s metadaty omezenými na scan-run a povinnými citacemi...",
      akbNoAnswer: "AKB vrátila explicitní no-answer.",
      akbCited: "AKB vrátila citovanou odpověď.",
      akbFailed: "AKB požadavek selhal.",
      authRequiredScan: "Před spuštěním skenů je vyžadována autentizace.",
      webTargetRequired: "Zadejte URL webu nebo API, které chcete zkontrolovat.",
      webTargetInvalid: "URL webu musí být platná http nebo https adresa.",
      buildingPlan: "Sestavuji scan plán...",
      queueingScan: "Zařazuji scan job do fronty...",
      planBlocked: "Plán skenu byl vytvořen, ale guardraily blokují spuštění.",
      planReady: "Plán skenu je připraven a lze jej zařadit do fronty.",
      scanQueued: "Scan job byl zařazen do fronty. Worker zapíše evidenci do /reports.",
      scanActionFailed: "Akce skenu selhala.",
      loadProfilesFallback: "Načtěte profily z lokálního API pro zahájení skenování."
    },
    runPanel: {
      title: "Spustit sken",
      aria: "Spustit sken",
      scanProfile: "Scan profil",
      findProfile: "Najít profil",
      targetType: "Typ cíle",
      directoryTarget: "Adresář",
      webTarget: "Web/API",
      webTargetUrl: "Web nebo API URL",
      webTargetPlaceholder: "https://example.cz",
      directoryTargetHelp: "Adresář vyberete registrací projektu. Cesta musí být uvnitř Docker mountu PROJECTS_ROOT_CONTAINER, typicky /workspace/projects/...",
      webTargetHelp: "Webový cíl používá vybraný webový/DAST profil s allowlistem hostu. Spouštějte ho jen proti vlastním nebo výslovně povoleným URL.",
      project: "Projekt",
      checks: "Kontroly",
      tools: "Nástroje",
      healthcareReady: (count: number) => `${count} zdravotnických připraveno`,
      notChecked: "nezkontrolováno",
      runScan: "Spustit sken",
      dryRun: "Dry run",
      openScanLog: "Otevřít log skenu",
      scanLogPending: "Otevřít detailní průběh běhu, evidenci a nálezy.",
      working: "Pracuji",
      plannedSteps: (count: number) => `${count} plánovaných kroků`,
      showBlockers: "Zobrazit blokery zralosti"
    },
    scanLog: {
      title: "Log a průběh skenu",
      scanRunId: "Scan run",
      loadedFromEvidence: "Načteno z lokální reportové evidence.",
      progress: "Průběh",
      completedSteps: (completed: number, total: number) => `${completed}/${total} kroků dokončeno`,
      status: "Stav",
      project: "Projekt",
      profile: "Profil",
      duration: "Doba běhu",
      evidenceRoot: "Evidence root",
      refresh: "Obnovit",
      openExecution: "Otevřít evidence view",
      exportPdf: "Export PDF",
      exportPptx: "Export PPTX",
      timeline: "Timeline kroků",
      evidenceFiles: "Soubory evidence",
      blockers: "Blokery gate",
      findings: "Nálezy",
      noRun: "Žádný běh skenu není vybraný",
      noRunDescription: "Spusťte sken nebo načtěte historii evidence pro zobrazení průběhu.",
      noSteps: "Zatím nejsou dostupné kroky běhu.",
      noFiles: "Zatím nejsou dostupné soubory evidence.",
      noBlockers: "Žádné blokery gate.",
      noFindings: "Žádné nálezy v načtené evidenci.",
      noLocation: "bez lokace"
    },
    detail: {
      title: "Funkční audit SecurityPreflight",
      close: "Zavřít",
      sidebar: "Sidebar",
      modal: "Modal",
      fullscreen: "Fullscreen",
      currentAssessment: "Aktuální hodnocení",
      body: "SecurityPreflight už není statický scaffold: scan execution, log běhu, prohlížení evidence, PDF/PPTX exporty a AKB bridge jsou zapojené. Referenční zdravotnická připravenost ještě vyžaduje triage nálezů, serverový live progress stream, autentizované sdílené nasazení a garance centrálního doručení.",
      p0Blockers: "P0 blokery"
    },
    command: {
      title: "SecurityPreflight příkazové centrum",
      placeholder: "Hledat obrazovky, reporty a akce",
      noResults: "Žádná odpovídající akce",
      open: "Otevřít",
      close: "Zavřít",
      actions: "Akce",
      preview: "STRATOS příkazová plocha pro navigaci, spuštění skenů a exporty reportů.",
      dashboardSubtitle: "Přehled SecurityPreflight",
      p0Gaps: (criticalGaps: number) => `${criticalGaps} P0 mezer`,
      noEvidenceLoaded: "Žádná evidence skenu není načtena",
      akbConfigured: "AKB nastaveno",
      akbNotConfigured: "AKB nenastaveno",
      runScan: "Spustit sken",
      queue: "Zařadit",
      dryRunPlan: "Dry-run scan plán",
      plan: "Plán",
      exportPdf: "Exportovat poslední report jako PDF",
      exportPptx: "Exportovat poslední report jako PPTX",
      noLatestRun: "Žádný poslední běh skenu",
      export: "Export"
    },
    toolbar: {
      filterCapabilities: "Filtrovat schopnosti",
      healthcareWarning: "zdravotnická reference vyžaduje uzavření P0 mezer"
    },
    sidebar: {
      subtitle: "STRATOS bezpečnostní workspace",
      localOnly: "pouze lokálně",
      workspaceMenu: "Navigace pracovního prostoru",
      headerActions: "Akce panelu",
      groupActions: "Akce submenu",
      itemActions: "Akce položky",
      openCommand: "Otevřít příkazové centrum",
      collapseSubmenus: "Skrýt submenu",
      openItem: "Otevřít položku",
      refreshData: "Obnovit data",
      openDetail: "Otevřít detail",
      dryRunItem: "Sestavit dry-run plán"
    },
    dates: {
      notAvailable: "není k dispozici"
    }
  },
  en: {
    language: "Language",
    languageCzech: "Czech",
    languageEnglish: "English",
    topbar: {
      applications: "STRATOS applications",
      userMenu: "User menu",
      settings: "Settings",
      logout: "Logout",
      commandCenter: "Command Center",
      doctor: "Doctor",
      checking: "Checking",
      audit: "Audit",
      userName: "Security analyst"
    },
    views: {
      workspace: "Workspace",
      dashboard: "Dashboard",
      capabilities: "Capability audit",
      execution: "Execution and evidence",
      executionShort: "Execution",
      telemetry: "Telemetry and AKB",
      telemetryShort: "Telemetry",
      backlog: "Backlog surfaces",
      findings: "Findings triage",
      reportsExports: "Reports and exports",
      security: "Security",
      evidence: "Evidence"
    },
    disabledReasons: {
      findings: "Needs persisted findings UI and exception workflow.",
      settings: "Settings surface is backlog."
    },
    statusLabels: {
      Ready: "Ready",
      Partial: "Partial",
      Gap: "Gap",
      Blocked: "Blocked",
      READY: "READY",
      PASS: "PASS",
      WARNING: "WARNING",
      FAIL: "FAIL",
      ERROR: "ERROR",
      idle: "idle",
      loading: "loading",
      success: "ready",
      error: "error",
      available: "available",
      container: "container",
      optional: "optional",
      completed: "completed",
      queued: "queued",
      running: "running",
      failed: "failed",
      missing: "missing",
      blocked: "blocked",
      ready: "ready",
      live: "live",
      fallback: "fallback",
      configured: "configured",
      "not configured": "not configured",
      implemented: "implemented",
      planned: "planned",
      empty: "empty",
      unknown: "unknown",
      source: "source"
    },
    scanProfiles: {
      "fast-local": {
        name: "Fast local",
        description: "Quick local feedback for secrets, documentation, OpenAPI, lightweight SAST, and filesystem SCA."
      },
      "pre-commit": {
        name: "Pre-commit",
        description: "Pre-commit gate for secrets, lightweight code checks, dependency scan, OpenAPI, and forbidden files."
      },
      "pre-release": {
        name: "Pre-release",
        description: "Release readiness profile with full scanners, documentation compliance, gate evaluation, and reports."
      },
      "api-security": {
        name: "API security",
        description: "OpenAPI JSON-first checks, ErrorResponse compliance, health/readiness endpoints, and safe runtime API probes."
      },
      "web-perimeter-safe": {
        name: "Safe web perimeter",
        description: "Safe DNS, TLS, port, HTTP header, endpoint discovery, WAF fingerprint, and Nuclei safe-template checks for an allowlisted web target."
      },
      "controlled-dast-local": {
        name: "Controlled local DAST",
        description: "Controlled OWASP ZAP baseline profile for localhost or explicitly allowlisted staging targets owned by the user."
      },
      "openapi-runtime-safe": {
        name: "Safe OpenAPI runtime",
        description: "OpenAPI contract checks, safe GET/HEAD runtime probes, and ZAP API scan for an explicitly allowlisted API target."
      },
      "external-vps-safe": {
        name: "External VPS safe scan",
        description: "Hardened external scanner VPS profile with ZAP baseline, Nuclei safe templates, and signed result return."
      },
      "enterprise-assurance": {
        name: "Enterprise assurance",
        description: "Healthcare evidence pipeline profile with Greenbone/OpenVAS import, OpenSCAP import/evaluation, DefectDojo SARIF export, and local SBOM/IaC evidence."
      },
      "container-security": {
        name: "Container security",
        description: "Dockerfile, image, and container misconfiguration readiness checks."
      },
      "documentation-compliance": {
        name: "Documentation compliance",
        description: "Mandatory repository documentation and minimum content checks."
      },
      "sensitive-data-ready": {
        name: "Sensitive data ready",
        description: "Strict readiness checks for health, hospital, and highly sensitive data systems."
      },
      "healthcare-reference": {
        name: "Healthcare reference",
        description: "Reference profile for healthcare and other highly sensitive systems requiring evidence, privacy, SBOM, API, IaC, and central-result export readiness."
      }
    },
    columns: {
      project: "Project",
      stack: "Stack",
      data: "Data",
      gate: "Gate",
      open: "Open",
      profile: "Profile",
      status: "Status",
      result: "Result",
      findings: "Findings",
      finished: "Finished",
      capability: "Capability",
      implemented: "Implemented",
      gap: "Gap",
      owner: "Owner",
      updated: "Updated"
    },
    dashboard: {
      maturityAria: "SecurityPreflight maturity summary",
      functionalMaturity: "Functional maturity",
      maturityDetail: (criticalGaps: number) => `${criticalGaps} P0 gaps remain before reference-grade healthcare use.`,
      scanProfiles: "Scan profiles",
      scanProfilesDetail: "Loaded from the local API contract.",
      toolchain: "Toolchain",
      notChecked: "not checked",
      toolchainDetail: (missing: number, error: number, optionalGap: boolean) =>
        `${missing} healthcare missing / ${error} error${optionalGap ? " / optional DAST gap" : ""}`,
      doctorDetail: "Run doctor to verify scanner availability.",
      reports: "Reports",
      reportsDetail: "STRATOS-style redacted exports plus central envelope v1.",
      projects: "Projects",
      registryPending: "registry UI pending",
      noProjects: "No projects",
      registeredProjects: "Registered projects",
      loadingProjects: "Loading projects",
      recentScans: "Recent scan runs",
      refreshing: "Refreshing",
      refresh: "Refresh",
      noCompletedEvidence: "No completed scan evidence yet",
      recentScansAria: "Recent scans",
      toolchainDoctor: "Toolchain doctor",
      dockerScannerStack: "Docker scanner stack",
      checked: "Checked",
      check: "Check",
      toolVersionFallback: "not reported"
    },
    projects: {
      registrationTitle: "Project registration",
      name: "Name",
      path: "Container path",
      owner: "Owner",
      dataClassification: "Data classification",
      repositoryUrl: "Repository URL",
      register: "Register project",
      registering: "Registering",
      refresh: "Refresh projects",
      selectProject: "Selected project",
      noSelectedProject: "No registered project",
      stackUnknown: "not detected",
      projectRegistered: (name: string) => `Project ${name} was registered.`,
      registrationFailed: "Project registration failed.",
      loadFailed: "Failed to load projects.",
      authRequired: "Authentication is required before managing projects.",
      pathHelp: "Enter an absolute container path inside PROJECTS_ROOT_CONTAINER, for example /workspace/projects/my-app.",
      classifications: {
        public: "public",
        internal: "internal",
        confidential: "confidential",
        sensitive: "sensitive",
        "health-data": "health data"
      }
    },
    capabilities: {
      title: "Overall functionality",
      body: "The application has a working local scan pipeline, OpenAPI contract, worker evidence, run log, report exports, and an AKB bridge aligned with STRATOS boundaries. The biggest gaps remain findings triage, server-side live progress streaming, production AKB/OIDC configuration, and shared-deployment security boundaries.",
      maturityEstimate: "Maturity estimate",
      maturityProgress: "Functional maturity",
      auditTitle: "Capability audit",
      p0Gaps: (criticalGaps: number) => `${criticalGaps} P0 gaps`,
      noMatching: "No matching capabilities",
      aria: "Capability audit"
    },
    execution: {
      lifecycle: "Execution lifecycle",
      lifecycleDescription: "Current end-to-end capability from local project to evidence",
      triageIncomplete: "triage incomplete",
      plannedChecks: "Planned checks in selected profile",
      planned: "planned",
      loadProfile: "Load a scan profile to see planned checks.",
      selectedChecks: "Selected scan profile checks",
      latestEvidence: "Latest report evidence",
      runScanForEvidence: "Run a scan to create report evidence",
      refresh: "Refresh",
      exportPdfLabel: "Export latest report as PDF",
      exportPdfTitle: "Export redacted PDF report",
      exportPptxLabel: "Export latest report as PPTX",
      exportPptxTitle: "Export redacted PPTX report",
      exportFilePdf: (file: string) => `Export ${file} report as PDF`,
      exportFilePptx: (file: string) => `Export ${file} report as PPTX`,
      exportScanPdf: "Export scan run as PDF",
      exportScanPptx: "Export scan run as PPTX",
      reportsPathEvidence: "REPORTS_PATH evidence",
      noEvidenceFiles: "No evidence files found",
      latestEvidenceAria: "Latest report evidence",
      latestSteps: "Latest run steps",
      stepDetailDescription: (findings: number, finished: string) => `${findings} findings · finished ${finished}`,
      selectScanForDetail: "Select or run a scan to load step detail",
      notLoaded: "not loaded",
      findingsCount: (count: number) => `${count} findings`,
      noFindings: "0 findings",
      noEvidenceFile: "no evidence file",
      noStepDetail: "No step detail loaded",
      latestStepsAria: "Latest run steps",
      reportExports: "Report exports",
      exporting: (format: string) => `Exporting ${format}`
    },
    telemetry: {
      title: "Telemetry and central storage",
      body: "The API exposes a v1 central ingest contract, the worker writes a redacted result envelope, and explicit opt-in can deliver results to a central sink or DefectDojo.",
      integrationPartial: "delivery optional",
      centralEnvelope: "Central result envelope",
      centralEnvelopeDescription: "Current contract and missing production controls",
      endpointImplemented: "contract-first ingest",
      redactedEnvelope: "Redacted worker envelope",
      noRawSource: "no raw source upload",
      deliveryStatus: "Delivery manifest",
      centralEvidenceNeeded: "audited in report evidence",
      authenticatedIntake: "Authenticated central intake",
      protectedBoundary: "protected API boundary available",
      authConfigIncomplete: "authentication configuration incomplete",
      centralTelemetryAria: "Central telemetry status",
      accessControl: "Access control",
      accessDescription: "STRATOS OIDC and production API boundary",
      signIn: "Sign in",
      signOut: "Sign out",
      apiAuthMode: "API authentication mode",
      sharedTokenOrLocal: "shared token or local development",
      rbacRoles: "RBAC roles",
      operatorRoles: (count: number) => `${count} operator roles`,
      notLoaded: "not loaded",
      browserBoundary: "Browser API boundary",
      corsAllowlist: "CORS allowlist",
      accessAria: "Access control status",
      bearerSession: "API bearer session",
      bearerToken: "Bearer token",
      useToken: "Use token",
      protectedApi: "Protected API",
      akbIntegration: "AKB integration",
      akbDescription: "Document-grounded AI boundary for STRATOS",
      akbRagEndpoint: "AKB RAG endpoint",
      setAkbBaseUrl: "set SECURITY_PREFLIGHT_AKB_RAG_BASE_URL",
      authenticationMode: "Authentication mode",
      authModeMeta: "caller bearer, OIDC client credentials, or service token",
      storageBoundary: "SecurityPreflight storage boundary",
      noLocalAiStorage: "no local AI storage",
      storageMeta: "prompts, responses, chunks and embeddings stay in AKB",
      citationsRequired: "Citations required",
      noAnswerMachineReadable: "no-answer is machine-readable",
      akbAria: "AKB integration status",
      askAkbTitle: "Ask AKB about latest scan",
      noScan: "no scan",
      question: "Question",
      askingAkb: "Asking AKB",
      askAkb: "Ask AKB",
      auditPrompt: "Audit prompt",
      auditPromptText: "What are the main security conclusions of the latest scan and which evidence supports them?",
      akbResponse: "AKB response",
      akbStatus: "AKB status",
      confidence: "confidence",
      citations: "Citations",
      akbCitation: "AKB citation",
      page: (page: number) => `page ${page}`,
      citationContext: "citation context"
    },
    auth: {
      authenticated: "Authenticated",
      required: "Auth required",
      localMode: "Local mode",
      initial: "Authentication status has not been checked yet.",
      oidcEstablished: "STRATOS OIDC session established.",
      oidcFailed: "OIDC login failed.",
      apiRequired: "Authentication is required for API access.",
      apiRequiredIncomplete: "Authentication is required but not fully configured.",
      localNoAuth: "Local development mode does not require API authentication.",
      statusUnavailable: "Authentication status is not available.",
      tokenCleared: "Authentication token cleared.",
      oidcNotConfigured: "STRATOS OIDC client is not configured."
    },
    messages: {
      exportInitial: "PDF/PPTX exports use redacted report evidence only.",
      akbInitial: "AKB answers are not stored in SecurityPreflight.",
      scanReady: "Ready to run a local scan through the Docker worker.",
      loadProfilesFailed: "Failed to load scan profiles.",
      loadRunsFailed: "Failed to load scan run history.",
      loadEvidenceFailed: "Failed to load scan evidence.",
      scanFinished: (gate: string) => `Scan finished with ${gate} gate.`,
      scanQueuedWaiting: "Scan job is queued; waiting for worker evidence.",
      scanQueuedNoEvidence: "Scan job was queued, but evidence is not available yet.",
      authRequiredDoctor: "Authentication is required before checking the toolchain.",
      doctorFailed: "Toolchain doctor failed.",
      akbStatusUnavailable: "AKB status is not available.",
      authRequiredExport: "Authentication is required before exporting reports.",
      noScanEvidence: "No scan run evidence is loaded yet.",
      generatingExport: (format: string) => `Generating ${format} export...`,
      exportGenerated: (format: string, fileName: string) => `${format} export generated: ${fileName}`,
      exportFailed: (format: string) => `${format} export failed.`,
      authRequiredAkb: "Authentication is required before asking AKB.",
      askingAkb: "Asking AKB with scan-run scoped metadata and required citations...",
      akbNoAnswer: "AKB returned an explicit no-answer.",
      akbCited: "AKB returned a cited response.",
      akbFailed: "AKB request failed.",
      authRequiredScan: "Authentication is required before running scans.",
      webTargetRequired: "Enter the web or API URL you want to check.",
      webTargetInvalid: "The web target must be a valid http or https URL.",
      buildingPlan: "Building scan plan...",
      queueingScan: "Queueing scan job...",
      planBlocked: "Scan plan was created, but guardrails block execution.",
      planReady: "Scan plan is ready and can be queued.",
      scanQueued: "Scan job was queued. Worker will write evidence under /reports.",
      scanActionFailed: "Scan action failed.",
      loadProfilesFallback: "Load profiles from the local API to start scanning."
    },
    runPanel: {
      title: "Run scan",
      aria: "Run scan",
      scanProfile: "Scan profile",
      findProfile: "Find profile",
      targetType: "Target type",
      directoryTarget: "Directory",
      webTarget: "Web/API",
      webTargetUrl: "Web or API URL",
      webTargetPlaceholder: "https://example.com",
      directoryTargetHelp: "Choose a directory by registering a project. The path must be inside the Docker PROJECTS_ROOT_CONTAINER mount, usually /workspace/projects/...",
      webTargetHelp: "The web target uses the selected web/DAST profile with the host allowlisted. Run it only against URLs you own or are explicitly allowed to test.",
      project: "Project",
      checks: "Checks",
      tools: "Tools",
      healthcareReady: (count: number) => `${count} healthcare ready`,
      notChecked: "not checked",
      runScan: "Run scan",
      dryRun: "Dry run",
      openScanLog: "Open scan log",
      scanLogPending: "Open detailed run progress, evidence, and findings.",
      working: "Working",
      plannedSteps: (count: number) => `${count} planned steps`,
      showBlockers: "Show maturity blockers"
    },
    scanLog: {
      title: "Scan Log and Progress",
      scanRunId: "Scan run",
      loadedFromEvidence: "Loaded from local report evidence.",
      progress: "Progress",
      completedSteps: (completed: number, total: number) => `${completed}/${total} steps completed`,
      status: "Status",
      project: "Project",
      profile: "Profile",
      duration: "Duration",
      evidenceRoot: "Evidence root",
      refresh: "Refresh",
      openExecution: "Open evidence view",
      exportPdf: "Export PDF",
      exportPptx: "Export PPTX",
      timeline: "Step timeline",
      evidenceFiles: "Evidence files",
      blockers: "Gate blockers",
      findings: "Findings",
      noRun: "No scan run is selected",
      noRunDescription: "Run a scan or load evidence history to show progress.",
      noSteps: "No run steps are available yet.",
      noFiles: "No evidence files are available yet.",
      noBlockers: "No gate blockers.",
      noFindings: "No findings in the loaded evidence.",
      noLocation: "no location"
    },
    detail: {
      title: "SecurityPreflight functional audit",
      close: "Close",
      sidebar: "Sidebar",
      modal: "Modal",
      fullscreen: "Fullscreen",
      currentAssessment: "Current assessment",
      body: "SecurityPreflight is beyond a static scaffold: scan execution, run log, evidence browsing, PDF/PPTX/SARIF exports, central delivery manifests and the AKB bridge are wired. Reference-grade healthcare operations still need findings triage, server-side live progress streaming, retention controls and production sink configuration.",
      p0Blockers: "P0 blockers"
    },
    command: {
      title: "SecurityPreflight Command Center",
      placeholder: "Search views, reports and actions",
      noResults: "No matching action",
      open: "Open",
      close: "Close",
      actions: "Actions",
      preview: "STRATOS command surface for navigation, scan execution and report exports.",
      dashboardSubtitle: "SecurityPreflight overview",
      p0Gaps: (criticalGaps: number) => `${criticalGaps} P0 gaps`,
      noEvidenceLoaded: "No scan evidence loaded",
      akbConfigured: "AKB configured",
      akbNotConfigured: "AKB not configured",
      runScan: "Run scan",
      queue: "Queue",
      dryRunPlan: "Dry-run scan plan",
      plan: "Plan",
      exportPdf: "Export latest report as PDF",
      exportPptx: "Export latest report as PPTX",
      noLatestRun: "No latest scan run",
      export: "Export"
    },
    toolbar: {
      filterCapabilities: "Filter capabilities",
      healthcareWarning: "healthcare reference requires P0 gap closure"
    },
    sidebar: {
      subtitle: "STRATOS security workspace",
      localOnly: "local only",
      workspaceMenu: "Workspace navigation",
      headerActions: "Panel actions",
      groupActions: "Submenu actions",
      itemActions: "Item actions",
      openCommand: "Open command center",
      collapseSubmenus: "Hide submenu",
      openItem: "Open item",
      refreshData: "Refresh data",
      openDetail: "Open detail",
      dryRunItem: "Build dry-run plan"
    },
    dates: {
      notAvailable: "not available"
    }
  }
} as const;

export function translateStatus(locale: AppLocale, status: string): string {
  return (uiText[locale].statusLabels as Record<string, string>)[status] ?? status;
}

export function translateGate(locale: AppLocale, gate: string): string {
  return (uiText[locale].statusLabels as Record<string, string>)[gate] ?? gate;
}

export function profileName(locale: AppLocale, profileId: string, fallback: string): string {
  return (uiText[locale].scanProfiles as Record<string, { name: string; description: string }>)[profileId]?.name ?? fallback;
}

export function profileDescription(locale: AppLocale, profileId: string, fallback: string): string {
  return (uiText[locale].scanProfiles as Record<string, { name: string; description: string }>)[profileId]?.description ?? fallback;
}
