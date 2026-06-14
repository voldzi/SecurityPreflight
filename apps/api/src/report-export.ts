import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { redactSecrets, type SeveritySummary } from "@security-preflight/core";

const require = createRequire(import.meta.url);
const PDFDocument = require("pdfkit") as new (options?: Record<string, unknown>) => {
  on(event: "data", callback: (chunk: Buffer) => void): void;
  on(event: "end", callback: () => void): void;
  end(): void;
  fontSize(size: number): ReturnType<typeof PDFDocument.prototype>;
  fillColor(color: string): ReturnType<typeof PDFDocument.prototype>;
  text(text: string, options?: Record<string, unknown>): ReturnType<typeof PDFDocument.prototype>;
  moveDown(lines?: number): ReturnType<typeof PDFDocument.prototype>;
  addPage(): ReturnType<typeof PDFDocument.prototype>;
  roundedRect(x: number, y: number, width: number, height: number, radius: number): ReturnType<typeof PDFDocument.prototype>;
  fill(color?: string): ReturnType<typeof PDFDocument.prototype>;
};
const PptxGen = require("pptxgenjs") as new () => {
  layout: string;
  author: string;
  company: string;
  subject: string;
  title: string;
  addSlide(): {
    background?: { color: string };
    addShape(shapeType: string, options: Record<string, unknown>): void;
    addText(text: string | Array<Record<string, unknown>>, options: Record<string, unknown>): void;
  };
  write(options: { outputType: "nodebuffer" }): Promise<unknown>;
};

export type ScanRunExportFormat = "PDF" | "PPTX";

export interface ScanRunExportSummary {
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
  severitySummary: SeveritySummary;
  evidence: {
    files: string[];
    hasCentralEnvelope: boolean;
  };
}

export interface ScanRunExportDetail extends ScanRunExportSummary {
  gate: {
    result: string;
    blockingReasons: string[];
  };
  findings: Array<{
    id: string;
    tool: string;
    severity: string;
    title: string;
    filePath: string | null;
    line: number | null;
    endpoint: string | null;
    recommendation: string;
  }>;
  steps: Array<{
    stepId: string;
    checkId: string;
    status: string;
    evidenceFile: string | null;
    findingCount: number;
    message: string | null;
  }>;
}

export interface BuildScanRunReportExportInput {
  format: ScanRunExportFormat;
  locale?: "cs" | "en";
  template?: string;
  run: ScanRunExportDetail;
  markdownReport?: string;
  generatedAt?: Date;
}

export interface ScanRunReportExport {
  reportType: "SECURITY_PREFLIGHT_SCAN";
  format: ScanRunExportFormat;
  fileName: string;
  mimeType: string;
  encoding: "base64";
  content: string;
  contentHash: string;
  generatedAt: string;
  parametersJson: {
    scanRunId: string;
    projectId: string;
    profileId: string;
    gateResult: string;
    findingCount: number;
    evidenceFiles: string[];
    template?: string;
  };
}

export async function buildScanRunReportExport(input: BuildScanRunReportExportInput): Promise<ScanRunReportExport> {
  const generatedAt = input.generatedAt ?? new Date();
  const content = input.format === "PPTX" ? await buildPptx(input) : await buildPdf(input);
  const contentHash = createHash("sha256").update(content).digest("hex");
  const dateKey = generatedAt.toISOString().slice(0, 10);
  const slug = slugify(`${input.run.project.name}-${input.run.id}`);

  return {
    reportType: "SECURITY_PREFLIGHT_SCAN",
    format: input.format,
    fileName: `security-preflight-${slug}-${dateKey}.${input.format.toLowerCase()}`,
    mimeType:
      input.format === "PPTX"
        ? "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        : "application/pdf",
    encoding: "base64",
    content: content.toString("base64"),
    contentHash,
    generatedAt: generatedAt.toISOString(),
    parametersJson: {
      scanRunId: input.run.id,
      projectId: input.run.project.id,
      profileId: input.run.profile.id,
      gateResult: input.run.gateResult,
      findingCount: input.run.findingCount,
      evidenceFiles: input.run.evidence.files,
      template: input.template
    }
  };
}

async function buildPdf(input: BuildScanRunReportExportInput): Promise<Buffer> {
  const run = input.run;
  const markdown = redactSecrets(input.markdownReport ?? buildPlainSummary(run));
  const lines: Array<[string, string]> = [
    ["Project", run.project.name],
    ["Scan run", run.id],
    ["Profile", run.profile.name],
    ["Data", run.project.dataClassification],
    ["Gate", run.gateResult.toUpperCase()],
    ["Findings", String(run.findingCount)],
    ["Started", run.startedAt ?? "not available"],
    ["Finished", run.finishedAt ?? "not available"]
  ];

  return new Promise((resolve) => {
    const doc = new PDFDocument({
      size: "A4",
      margin: 48,
      info: {
        Title: `SecurityPreflight ${run.id}`,
        Author: "SecurityPreflight",
        Subject: "STRATOS security preflight report"
      }
    });
    const chunks: Buffer[] = [];

    doc.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    doc.on("end", () => resolve(Buffer.concat(chunks)));

    doc.fontSize(22).fillColor("#0f172a").text("SecurityPreflight report");
    doc.moveDown(0.3);
    doc.fontSize(10).fillColor("#64748b").text("STRATOS evidence export. Raw scanner stdout, secrets and source code are not included.");
    doc.moveDown(1);

    for (const [label, value] of lines) {
      doc.fontSize(10).fillColor("#64748b").text(label, { continued: true, width: 120 });
      doc.fillColor("#0f172a").text(`  ${redactSecrets(value)}`);
    }

    doc.moveDown(1);
    doc.fontSize(16).fillColor("#0f172a").text("Severity summary");
    doc.moveDown(0.3);
    for (const [label, value] of Object.entries(run.severitySummary)) {
      doc.fontSize(10).fillColor("#0f172a").text(`${label}: ${value}`);
    }

    doc.moveDown(1);
    doc.fontSize(16).fillColor("#0f172a").text("Top findings");
    const findings = run.findings.slice(0, 12);
    if (!findings.length) {
      doc.fontSize(10).fillColor("#166534").text("No findings in the redacted report evidence.");
    } else {
      for (const finding of findings) {
        doc.moveDown(0.4);
        doc.fontSize(11).fillColor("#0f172a").text(`${finding.severity.toUpperCase()} - ${redactSecrets(finding.title)}`);
        doc.fontSize(9).fillColor("#475569").text(redactSecrets([finding.tool, finding.filePath, finding.endpoint].filter(Boolean).join(" | ")));
        doc.fontSize(9).fillColor("#334155").text(redactSecrets(finding.recommendation));
      }
    }

    doc.addPage();
    doc.fontSize(16).fillColor("#0f172a").text("Markdown evidence excerpt");
    doc.moveDown(0.5);
    doc.fontSize(8).fillColor("#334155").text(markdown.slice(0, 9000));
    doc.end();
  });
}

async function buildPptx(input: BuildScanRunReportExportInput): Promise<Buffer> {
  const run = input.run;
  const pptx = new PptxGen();
  pptx.layout = "LAYOUT_WIDE";
  pptx.author = "SecurityPreflight";
  pptx.company = "STRATOS";
  pptx.subject = "Security preflight report";
  pptx.title = `SecurityPreflight ${run.id}`;

  const summaryRows = [
    `Project: ${run.project.name}`,
    `Profile: ${run.profile.name}`,
    `Data: ${run.project.dataClassification}`,
    `Status: ${run.status}`,
    `Gate: ${run.gateResult.toUpperCase()}`,
    `Findings: ${run.findingCount}`
  ];

  const titleSlide = pptx.addSlide();
  titleSlide.background = { color: "F8FAFC" };
  addHeader(titleSlide, "SecurityPreflight", "STRATOS security preflight");
  titleSlide.addText(redactSecrets(run.project.name), { x: 0.65, y: 1.65, w: 11.5, h: 0.45, fontSize: 24, bold: true, color: "0F172A" });
  titleSlide.addText(redactSecrets(run.id), { x: 0.65, y: 2.18, w: 11.5, h: 0.28, fontSize: 11, color: "475569" });
  titleSlide.addShape("rect", { x: 0.65, y: 3.0, w: 3.1, h: 1.35, fill: { color: gateColor(run.gateResult) }, line: { color: gateColor(run.gateResult) }, radius: 0.12 });
  titleSlide.addText(run.gateResult.toUpperCase(), { x: 0.9, y: 3.32, w: 2.55, h: 0.38, fontSize: 22, bold: true, color: "FFFFFF", align: "center" });
  titleSlide.addText(summaryRows.join("\n"), { x: 4.15, y: 2.9, w: 7.8, h: 1.8, fontSize: 14, color: "0F172A", breakLine: false, fit: "shrink" });

  const severitySlide = pptx.addSlide();
  severitySlide.background = { color: "FFFFFF" };
  addHeader(severitySlide, "Gate and severity", run.id);
  const severityEntries = Object.entries(run.severitySummary);
  severityEntries.forEach(([severity, count], index) => {
    const x = 0.65 + index * 2.45;
    severitySlide.addShape("rect", { x, y: 1.55, w: 2.1, h: 1.45, fill: { color: severityColor(severity) }, line: { color: severityColor(severity) }, radius: 0.08 });
    severitySlide.addText(String(count), { x: x + 0.15, y: 1.82, w: 1.8, h: 0.38, fontSize: 24, bold: true, color: "FFFFFF", align: "center" });
    severitySlide.addText(severity.toUpperCase(), { x: x + 0.15, y: 2.32, w: 1.8, h: 0.25, fontSize: 9, bold: true, color: "FFFFFF", align: "center" });
  });
  severitySlide.addText(redactSecrets(run.gate.blockingReasons.length ? run.gate.blockingReasons.join("\n") : "No blocking reasons in the redacted report evidence."), {
    x: 0.65,
    y: 3.55,
    w: 11.8,
    h: 1.4,
    fontSize: 13,
    color: "334155",
    fit: "shrink"
  });

  const findingsSlide = pptx.addSlide();
  findingsSlide.background = { color: "FFFFFF" };
  addHeader(findingsSlide, "Top findings", `${run.findingCount} total`);
  findingsSlide.addText(
    run.findings.length
      ? run.findings
          .slice(0, 8)
          .map((finding) => `${finding.severity.toUpperCase()} - ${redactSecrets(finding.title)} (${redactSecrets(finding.tool)})`)
          .join("\n")
      : "No findings in the redacted report evidence.",
    { x: 0.65, y: 1.45, w: 11.8, h: 4.8, fontSize: 14, color: "0F172A", breakLine: false, fit: "shrink" }
  );

  const evidenceSlide = pptx.addSlide();
  evidenceSlide.background = { color: "F8FAFC" };
  addHeader(evidenceSlide, "Evidence manifest", run.evidence.hasCentralEnvelope ? "central envelope ready" : "local evidence only");
  evidenceSlide.addText(redactSecrets(run.evidence.files.join("\n")), { x: 0.65, y: 1.35, w: 11.8, h: 4.9, fontSize: 12, color: "0F172A", fit: "shrink" });
  evidenceSlide.addText("Export excludes raw scanner stdout/stderr and source code.", { x: 0.65, y: 6.65, w: 11.8, h: 0.25, fontSize: 10, color: "64748B" });

  const payload = await pptx.write({ outputType: "nodebuffer" });
  return Buffer.isBuffer(payload) ? payload : Buffer.from(payload as ArrayBuffer);
}

function addHeader(slide: ReturnType<InstanceType<typeof PptxGen>["addSlide"]>, title: string, subtitle: string): void {
  slide.addText(title, { x: 0.65, y: 0.45, w: 7.8, h: 0.35, fontSize: 22, bold: true, color: "0F172A" });
  slide.addText(subtitle, { x: 0.65, y: 0.86, w: 7.8, h: 0.22, fontSize: 10, color: "64748B" });
  slide.addShape("rect", { x: 10.55, y: 0.5, w: 1.65, h: 0.36, fill: { color: "0F172A" }, line: { color: "0F172A" }, radius: 0.06 });
  slide.addText("STRATOS", { x: 10.78, y: 0.58, w: 1.2, h: 0.16, fontSize: 8, bold: true, color: "FFFFFF", align: "center" });
}

function buildPlainSummary(run: ScanRunExportDetail): string {
  return [
    "# SecurityPreflight Report",
    "",
    `Project: ${run.project.name}`,
    `Scan run: ${run.id}`,
    `Profile: ${run.profile.name}`,
    `Gate: ${run.gateResult}`,
    `Findings: ${run.findingCount}`,
    "",
    "## Evidence",
    ...run.evidence.files.map((file) => `- ${file}`)
  ].join("\n");
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || "scan";
}

function gateColor(value: string): string {
  if (value === "pass") return "166534";
  if (value === "warning") return "B45309";
  if (value === "fail" || value === "error") return "B91C1C";
  return "475569";
}

function severityColor(value: string): string {
  if (value === "critical") return "7F1D1D";
  if (value === "high") return "B91C1C";
  if (value === "medium") return "B45309";
  if (value === "low") return "2563EB";
  return "475569";
}
