import React from 'react';
import {
  BookOpen,
  Shield,
  Layers,
  Cpu,
  Lock,
  AlertTriangle,
  CheckCircle,
  FileSearch,
} from 'lucide-react';

export const MethodologyPage: React.FC = () => {
  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-in fade-in duration-150">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800">
            TECHNICAL SPECIFICATION
          </span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          Analysis Methodology & Scoring Framework
        </h1>
        <p className="mt-2 text-xs sm:text-sm text-slate-400 leading-relaxed">
          Detailed technical documentation on the deterministic risk engine, bounded static inspection heuristics, evidence attribution, and zero-execution safeguards.
        </p>
      </div>

      {/* Section 1: Risk Scoring Model */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl space-y-4">
        <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyan-400" />
          <span>1. Deterministic Risk Scoring Model (0–100)</span>
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          The SecureMailAnalyzer risk scoring engine evaluates detected static indicators using a transparent, explainable tiered formula. Rather than a black-box machine learning probability, every point in the score is explicitly attributed to concrete structural evidence:
        </p>

        {/* Thresholds Table */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-4 rounded-xl bg-emerald-950/30 border border-emerald-800/50 space-y-1">
            <span className="text-emerald-400 font-bold block text-sm">LOW (0–24)</span>
            <p className="text-slate-300 font-sans text-[11px]">
              No overt static signatures matched within inspected bounds. Normal structural characteristics.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-800/50 space-y-1">
            <span className="text-amber-400 font-bold block text-sm">MEDIUM (25–49)</span>
            <p className="text-slate-300 font-sans text-[11px]">
              Suspicious characteristics, macro-enabled extensions, or external hyperlinks requiring analyst review.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-orange-950/30 border border-orange-800/50 space-y-1">
            <span className="text-orange-400 font-bold block text-sm">HIGH (50–74)</span>
            <p className="text-slate-300 font-sans text-[11px]">
              Strong indicators of weaponization: double extensions, embedded VBA projects, or PDF JavaScript actions.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/50 space-y-1">
            <span className="text-rose-400 font-bold block text-sm">CRITICAL (75–100)</span>
            <p className="text-slate-300 font-sans text-[11px]">
              Severe weaponization: compiled Windows PE binary disguised with decoy extension, zip slips, or destructive commands.
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-300">
          <span className="text-slate-500 font-sans text-[11px] block uppercase font-semibold">Mathematical Formula:</span>
          Score = min(100, BaseSeverityFloor + Sum(SecondaryFindingsBonus))
        </div>
      </div>

      {/* Section 2: Signature Feature: Attachment Threat Story */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl space-y-4">
        <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
          <Layers className="w-5 h-5 text-cyan-400" />
          <span>2. Attachment Threat Story & Provenance Attribution</span>
        </h2>
        <p className="text-xs text-slate-300 leading-relaxed">
          The signature capability of this platform is the chronological correlation of all investigation findings into an explainable narrative. Evidence source attribution is rigorously preserved at every step:
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900 border border-cyan-800/50 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-700">
                Observed
              </span>
              <span className="font-bold text-white">Direct Static Inspection</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              Evidence directly extracted by SecureMailAnalyzer's in-memory stream parser. Includes magic byte headers, SHA-256 calculation, and bounded regex evaluations.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-purple-800/50 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-700">
                Imported Sandbox Report
              </span>
              <span className="font-bold text-white">External Behavioral Telemetry</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              Behavioral events (process creation, network beacons, registry modifications) imported from user-supplied dynamic sandbox reports. Strictly non-executed on local system.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-emerald-800/50 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-700">
                Application Action
              </span>
              <span className="font-bold text-white">Platform Operations</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              Actions taken by the SecureMailAnalyzer platform itself, including file intake, cryptographic hashing, risk computation, and analyst quarantine simulation state changes.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-900 border border-amber-800/50 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                Synthetic Demo Data
              </span>
              <span className="font-bold text-white">Demonstration Fixtures</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              Pre-packaged safe synthetic fixtures designed for presentation and functional verification without exposing systems to malicious payloads.
            </p>
          </div>
        </div>
      </div>

      {/* Section 3: Detection Rules Catalog */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl space-y-4">
        <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
          <FileSearch className="w-5 h-5 text-cyan-400" />
          <span>3. Core Static Detection Rules Catalog</span>
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900 text-slate-400 uppercase font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Rule ID</th>
                <th className="py-2.5 px-3">Title</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Mechanism</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300 font-mono text-[11px]">
              <tr>
                <td className="py-2.5 px-3 text-cyan-400">RULE-EXT-MISMATCH-EXE</td>
                <td className="py-2.5 px-3 font-sans font-medium text-white">Disguised Windows PE Executable</td>
                <td className="py-2.5 px-3 text-rose-400">CRITICAL</td>
                <td className="py-2.5 px-3 font-sans">Magic bytes '4D 5A' (MZ) found in non-executable extension</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-400">RULE-DOUBLE-EXTENSION</td>
                <td className="py-2.5 px-3 font-sans font-medium text-white">Deceptive Double Extension</td>
                <td className="py-2.5 px-3 text-orange-400">HIGH</td>
                <td className="py-2.5 px-3 font-sans">Decoy doc extension followed by executable/script extension</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-400">RULE-PDF-JAVASCRIPT</td>
                <td className="py-2.5 px-3 font-sans font-medium text-white">Embedded PDF JavaScript / Action</td>
                <td className="py-2.5 px-3 text-orange-400">HIGH</td>
                <td className="py-2.5 px-3 font-sans">Detection of /JavaScript or /JS objects in PDF catalog stream</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-400">RULE-OFFICE-MACRO-CONTAINER</td>
                <td className="py-2.5 px-3 font-sans font-medium text-white">VBA Macro Project Stream</td>
                <td className="py-2.5 px-3 text-orange-400">HIGH</td>
                <td className="py-2.5 px-3 font-sans">Safe in-memory ZIP scan reveals word/vbaProject.bin</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-400">RULE-STRING-HIGH</td>
                <td className="py-2.5 px-3 font-sans font-medium text-white">Encoded PowerShell Invocation</td>
                <td className="py-2.5 px-3 text-orange-400">HIGH</td>
                <td className="py-2.5 px-3 font-sans">Regex match for -enc, -w hidden, or -ep bypass flags</td>
              </tr>
              <tr>
                <td className="py-2.5 px-3 text-cyan-400">RULE-ARCHIVE-PATH-TRAVERSAL</td>
                <td className="py-2.5 px-3 font-sans font-medium text-white">Zip Slip Directory Traversal</td>
                <td className="py-2.5 px-3 text-rose-400">CRITICAL</td>
                <td className="py-2.5 px-3 font-sans">Archive entry contains relative '../' traversal sequences</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Section 4: Mandatory Safeguards & Limitations */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl space-y-4">
        <h2 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-amber-400" />
          <span>4. Mandatory System Safeguards & Limitations</span>
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-300">
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white">Zero Host Execution Guarantee</h3>
            <p className="leading-relaxed">
              Uploaded attachments are never executed, passed to subprocesses, or opened via system handlers. Archive files are parsed strictly in-memory without host disk extraction.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white">Bounded Resource Safeguards</h3>
            <p className="leading-relaxed">
              Inspection is bounded to a maximum file size of 25 MB and 2 MB stream inspection, protecting analysis workers from decompression bombs (Zip Bombs) and CPU exhaustion.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white">The Low Score Disclaimer</h3>
            <p className="leading-relaxed">
              A Low risk score (0–24) confirms only that no recognized static heuristics matched within the inspected bounds. It does NOT guarantee that the attachment is proven benign.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
            <h3 className="font-bold text-white">Simulated Quarantine Scope</h3>
            <p className="leading-relaxed">
              Quarantine workflows represent simulated SOC tracking records rather than kernel-level filesystem containment or antivirus sandbox virtualization.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
