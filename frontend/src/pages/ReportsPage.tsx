import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  Copy,
  Check,
  Shield,
  Layers,
  Clock,
  AlertTriangle,
  FileCode,
  FileSpreadsheet,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { fetchInvestigation, fetchInvestigations, getExportCsvUrl, getExportJsonUrl } from '../services/api';
import { Investigation } from '../types';

interface ReportsPageProps {
  initialInvestigationId?: string;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ initialInvestigationId }) => {
  const [investigationsList, setInvestigationsList] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<string>(initialInvestigationId || '');
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    fetchInvestigations('', '', 50, 0)
      .then((data) => {
        setInvestigationsList(data.investigations);
        if (!selectedId && data.investigations.length > 0) {
          setSelectedId(data.investigations[0].id);
        }
      })
      .catch((err) => console.error('Failed to list investigations', err));
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    setLoading(true);
    fetchInvestigation(selectedId)
      .then((data) => setInvestigation(data))
      .catch((err) => setError(err.message || 'Failed to load report data'))
      .finally(() => setLoading(false));
  }, [selectedId]);

  const copyIncidentSummary = () => {
    if (!investigation) return;
    const text = `
=== SECUREMAILANALYZER SOC INCIDENT REPORT ===
Investigation ID: ${investigation.id}
Timestamp: ${investigation.created_at}
Attachment: ${investigation.original_filename} (${investigation.file_size} bytes)
Format: ${investigation.detected_format}
SHA-256: ${investigation.sha256}
Risk Assessment: ${investigation.severity} (Score: ${investigation.risk_score}/100)
Verdict: ${investigation.verdict}
Quarantine Status: ${investigation.quarantine_status}

DETECTION FINDINGS (${investigation.findings.length}):
${investigation.findings.map((f, i) => `${i + 1}. [${f.severity}] ${f.title} (${f.rule_id}) - ${f.evidence}`).join('\n')}

CORRELATED THREAT STORY EVENTS (${investigation.timeline.length}):
${investigation.timeline.map((e, i) => `${i + 1}. [${e.source}] ${e.title} - ${e.description}`).join('\n')}

METHODOLOGY & DISCLAIMER:
Deterministic static heuristic analysis. Low score indicates zero static signatures detected, not certified benign proof.
==============================================
`.trim();

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <span>Security Reports & Artifact Exports</span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Export comprehensive machine-readable JSON and RFC 4180 CSV incident reports with full evidence attribution.
          </p>
        </div>

        {/* Picker */}
        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Target Investigation:</span>
          <select
            value={selectedId}
            onChange={(e) => setSelectedId(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono text-xs focus:outline-none focus:border-cyan-500 max-w-xs"
          >
            {investigationsList.map((inv) => (
              <option key={inv.id} value={inv.id}>
                {inv.id} — {inv.filename}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {investigation && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Export Action Cards */}
          <div className="space-y-4">
            {/* JSON Export Card */}
            <div className="p-5 rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl space-y-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-cyan-950 text-cyan-400 border border-cyan-800">
                  <FileCode className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">Full JSON Report</h3>
                  <p className="text-[11px] text-slate-400">Structured telemetry, findings & timeline</p>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Contains complete metadata, cryptographic SHA-256 hashes, rule contributions, timeline events with source badges, and quarantine records.
              </p>
              <a
                href={getExportJsonUrl(investigation.id)}
                download
                className="w-full py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 transition shadow-md shadow-cyan-950/40"
              >
                <Download className="w-4 h-4" />
                <span>Download Report (JSON)</span>
              </a>
            </div>

            {/* CSV Export Card */}
            <div className="p-5 rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl space-y-3">
              <div className="flex items-center gap-3">
                <div className="p-2.5 rounded-xl bg-emerald-950 text-emerald-400 border border-emerald-800">
                  <FileSpreadsheet className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">CSV Executive Summary</h3>
                  <p className="text-[11px] text-slate-400">Spreadsheet-compatible audit table</p>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                RFC 4180 compliant CSV export formatted for import into security SIEMs, ticketing tools, or spreadsheets.
              </p>
              <a
                href={getExportCsvUrl(investigation.id)}
                download
                className="w-full py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center justify-center gap-2 transition shadow-md shadow-emerald-950/40"
              >
                <Download className="w-4 h-4" />
                <span>Download Summary (CSV)</span>
              </a>
            </div>

            {/* Copy Clipboard Card */}
            <div className="p-5 rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl space-y-3">
              <h3 className="text-sm font-bold text-white">SOC Incident Ticket Brief</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Formatted markdown summary ready to paste directly into Jira, ServiceNow, or Slack incident channels.
              </p>
              <button
                onClick={copyIncidentSummary}
                className="w-full py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-semibold text-xs flex items-center justify-center gap-2 transition"
              >
                {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-cyan-400" />}
                <span>{copied ? 'Copied to Clipboard!' : 'Copy Incident Summary'}</span>
              </button>
            </div>
          </div>

          {/* Live Preview Panel */}
          <div className="lg:col-span-2 rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span>Report Preview: {investigation.id}</span>
              </h2>
              <RiskBadge severity={investigation.severity} score={investigation.risk_score} size="sm" />
            </div>

            {/* Overview Details */}
            <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-slate-900 p-4 rounded-xl border border-slate-800">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Original Filename</span>
                <span className="text-white font-semibold">{investigation.original_filename}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">SHA-256 Hash</span>
                <span className="text-cyan-400 truncate block">{investigation.sha256}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Format & Size</span>
                <span className="text-slate-200">{investigation.detected_format} ({(investigation.file_size / 1024).toFixed(1)} KB)</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Quarantine Status</span>
                <span className="text-amber-400 font-semibold">{investigation.quarantine_status}</span>
              </div>
            </div>

            {/* Findings Preview */}
            <div>
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                Static Findings Included ({investigation.findings.length})
              </h3>
              <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                {investigation.findings.map((f, i) => (
                  <div key={i} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs flex items-center justify-between">
                    <div>
                      <span className="font-mono text-cyan-400 text-[11px] mr-2">[{f.rule_id}]</span>
                      <span className="text-white font-medium">{f.title}</span>
                    </div>
                    <span className="font-mono text-amber-400">+{f.contribution} pts</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Timeline Preview */}
            <div>
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                Attachment Threat Story Events ({investigation.timeline.length})
              </h3>
              <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1 font-mono text-[11px]">
                {investigation.timeline.map((e, i) => (
                  <div key={i} className="p-2 rounded bg-slate-950 border border-slate-800 flex items-center justify-between text-slate-300">
                    <span className="truncate max-w-[340px]">
                      <span className="text-cyan-400">[{e.source}]</span> {e.title}
                    </span>
                    <span className="text-slate-500 text-[10px] shrink-0">{new Date(e.timestamp).toLocaleTimeString()}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
