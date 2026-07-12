"use client";

import { Activity, Archive, Bot, FileWarning, ScrollText, Sparkles } from "lucide-react";
import {
  Badge,
  Button,
  DataGridShell,
  ProgressBar,
  type BadgeTone
} from "@voldzi/stratos-ui";

type ProgressTone = "default" | "good" | "warning" | "danger";

export interface ScanProgressStep {
  id: string;
  title: string;
  status: string;
  statusLabel: string;
  findingLabel?: string;
}

export interface ScanProgressPanelProps {
  title: string;
  badgeTone: BadgeTone;
  badgeLabel: string;
  scanIsActive: boolean;
  activeRunId: string;
  completedLabel: string;
  progressValue: number;
  progressTone: ProgressTone;
  progressLabel: string;
  steps: ScanProgressStep[];
  latestOutcomeLabel: string;
  findingsTitle: string;
  findingsValue: string;
  findingsMeta: string;
  evidenceTitle: string;
  evidenceValue: string;
  evidenceMeta: string;
  codexTitle: string;
  codexValue: string;
  codexMeta: string;
  akbTitle: string;
  akbValue: string;
  akbMeta: string;
  openExecutionLabel: string;
  exportCodexLabel: string;
  askAkbLabel: string;
  askAkbBusyLabel: string;
  canOpenExecution: boolean;
  canExportCodex: boolean;
  canAskAkb: boolean;
  exportingCodex: boolean;
  askingAkb: boolean;
  onOpenExecution: () => void;
  onExportCodex: () => void;
  onAskAkb: () => void;
}

export function ScanProgressPanel({
  title,
  badgeTone,
  badgeLabel,
  scanIsActive,
  activeRunId,
  completedLabel,
  progressValue,
  progressTone,
  progressLabel,
  steps,
  latestOutcomeLabel,
  findingsTitle,
  findingsValue,
  findingsMeta,
  evidenceTitle,
  evidenceValue,
  evidenceMeta,
  codexTitle,
  codexValue,
  codexMeta,
  akbTitle,
  akbValue,
  akbMeta,
  openExecutionLabel,
  exportCodexLabel,
  askAkbLabel,
  askAkbBusyLabel,
  canOpenExecution,
  canExportCodex,
  canAskAkb,
  exportingCodex,
  askingAkb,
  onOpenExecution,
  onExportCodex,
  onAskAkb
}: ScanProgressPanelProps) {
  return (
    <DataGridShell
      title={<strong>{title}</strong>}
      toolbar={<Badge tone={badgeTone}>{badgeLabel}</Badge>}
      className="security-grid-shell"
    >
      <div className={`security-live-scan${scanIsActive ? " is-running" : ""}`}>
        <div className="security-live-orb" aria-hidden="true">
          <Activity size={28} />
        </div>
        <div className="security-live-copy">
          <span>{activeRunId}</span>
          <strong>{completedLabel}</strong>
          <ProgressBar value={progressValue} tone={progressTone} label={progressLabel} />
        </div>
        <div className="security-live-steps">
          {steps.map((step, index) => (
            <div key={step.id} className="security-live-step" data-status={step.status.toLowerCase()}>
              <span>{index + 1}</span>
              <strong>{step.title}</strong>
              <small>{step.findingLabel ?? step.statusLabel}</small>
            </div>
          ))}
        </div>
        <div className="security-live-handoff" aria-label={latestOutcomeLabel}>
          <div className="security-live-handoff-card">
            <span>
              <FileWarning size={14} aria-hidden="true" />
              {findingsTitle}
            </span>
            <strong>{findingsValue}</strong>
            <p>{findingsMeta}</p>
          </div>
          <div className="security-live-handoff-card">
            <span>
              <Archive size={14} aria-hidden="true" />
              {evidenceTitle}
            </span>
            <strong>{evidenceValue}</strong>
            <p>{evidenceMeta}</p>
          </div>
          <div className="security-live-handoff-card">
            <span>
              <ScrollText size={14} aria-hidden="true" />
              {codexTitle}
            </span>
            <strong>{codexValue}</strong>
            <p>{codexMeta}</p>
          </div>
          <div className="security-live-handoff-card">
            <span>
              <Bot size={14} aria-hidden="true" />
              {akbTitle}
            </span>
            <strong>{akbValue}</strong>
            <p>{akbMeta}</p>
          </div>
        </div>
        <div className="security-live-actions">
          <Button disabled={!canOpenExecution} onClick={onOpenExecution} size="compact">
            <Archive size={14} />
            {openExecutionLabel}
          </Button>
          <Button disabled={!canAskAkb || askingAkb} onClick={onAskAkb} size="compact">
            <Bot size={14} />
            {askingAkb ? askAkbBusyLabel : askAkbLabel}
          </Button>
          <Button variant="primary" disabled={!canExportCodex || exportingCodex} onClick={onExportCodex} size="compact">
            <Sparkles size={14} />
            {exportCodexLabel}
          </Button>
        </div>
      </div>
    </DataGridShell>
  );
}
