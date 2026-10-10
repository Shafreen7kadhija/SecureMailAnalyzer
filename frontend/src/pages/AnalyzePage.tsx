import React, { useState, useEffect } from 'react';
import {
  Upload,
  File,
  Shield,
  AlertTriangle,
  CheckCircle,
  FileText,
  Hash,
  Clock,
  Sparkles,
  ArrowRight,
  Download,
  Lock,
  Layers,
  Cpu,
  RefreshCw,
  Info,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { QuarantineModal } from '../components/QuarantineModal';
import { SandboxImportModal } from '../components/SandboxImportModal';
import {
  fetchSamples,
  getExportCsvUrl,
  getExportJsonUrl,
  triggerSampleAnalysis,
  uploadAndAnalyzeFile,
} from '../services/api';
import { Investigation, SampleFixture } from '../types';

interface AnalyzePageProps {
  onNavigateToStory: (investigationId: string) => void;
  initialInvestigation?: Investigation | null;
}

export const AnalyzePage: React.FC<AnalyzePageProps> = ({
  onNavigateToStory,
  initialInvestigation,
}) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [samples, setSamples] = useState<SampleFixture[]>([]);
  const [investigation, setInvestigation] = useState<Investigation | null>(initialInvestigation || null);
  const [loading, setLoading] = useState<boolean>(false);
  const [loadingSampleId, setLoadingSampleId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState<boolean>(false);

  // Modals state
  const [isQuarantineOpen, setIsQuarantineOpen] = useState<boolean>(false);
  const [isSandboxOpen, setIsSandboxOpen] = useState<boolean>(false);

  useEffect(() => {
    fetchSamples()
      .then(setSamples)
      .catch((err) => console.error('Failed to load sample fixtures catalog', err));
  }, []);

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleAnalyzeUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;

    setLoading(true);
    setError(null);
    try {
      const result = await uploadAndAnalyzeFile(selectedFile, false);
      setInvestigation(result);
    } catch (err: any) {
      setError(err.message || 'File analysis failed');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadSample = async (sampleId: string) => {
    setLoadingSampleId(sampleId);
    setError(null);
    try {
      const result = await triggerSampleAnalysis(sampleId);
      setInvestigation(result);
    } catch (err: any) {
      setError(err.message || 'Sample analysis failed');
    } finally {
      setLoadingSampleId(null);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-150">
      {/* Top Header */}
      <div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight flex items-center gap-2">
          <span>Attachment Threat Analysis</span>
          <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
            STATIC ENGINE
          </span>
        </h1>
        <p className="mt-1 text-xs sm:text-sm text-slate-400">
          Upload any email attachment or load synthetic demonstration fixtures for instant bounded inspection, hash calculation, and explainable risk scoring.
        </p>
      </div>

      {/* Upload & Quick Demo Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Upload Dropzone */}
        <div className="lg:col-span-2 rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl">
          <h2 className="text-sm font-bold text-white uppercase tracking-wider mb-4 flex items-center gap-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            <span>Upload Email Attachment</span>
          </h2>

          <form onSubmit={handleAnalyzeUpload} className="space-y-4">
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all ${
                dragActive
                  ? 'border-cyan-400 bg-cyan-950/20'
                  : 'border-slate-700 hover:border-slate-600 bg-slate-900/50'
              }`}
            >
              <input
                type="file"
                id="file-upload"
                onChange={handleFileChange}
                className="hidden"
              />
              <label htmlFor="file-upload" className="cursor-pointer block">
                <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto mb-3 text-cyan-400">
                  <Upload className="w-6 h-6" />
                </div>
                <p className="text-sm font-semibold text-white">
                  {selectedFile ? selectedFile.name : 'Choose attachment or drag & drop'}
                </p>
                <p className="text-xs text-slate-400 mt-1">
                  Supports Office docs, PDFs, Archives, Scripts, and Executables (Max 25 MB)
                </p>
              </label>
            </div>

            {/* Selected File Pre-inspection card */}
            {selectedFile && (
              <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2.5 truncate">
                  <File className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span className="text-white font-medium truncate">{selectedFile.name}</span>
                  <span className="text-slate-400">({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedFile(null)}
                  className="text-slate-400 hover:text-rose-400 text-[11px] font-sans"
                >
                  Clear
                </button>
              </div>
            )}

            {error && (
              <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={!selectedFile || loading}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-bold text-sm shadow-lg shadow-cyan-500/20 transition flex items-center justify-center gap-2"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                  <span>Inspecting Bounded Byte Stream & Hashes...</span>
                </>
              ) : (
                <>
                  <Shield className="w-4 h-4" />
                  <span>Run Safe Static Threat Inspection</span>
                </>
              )}
            </button>
          </form>
        </div>

        {/* 1-Click Demo Samples Box (Hackathon Superpower!) */}
        <div className="rounded-2xl bg-gradient-to-b from-[#10172e] to-[#0f172a] border border-cyan-900/40 p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">Ready-to-Use Demo Samples</h2>
            </div>
            <p className="text-xs text-slate-300 mb-4 leading-relaxed">
              Instantly analyze pre-configured safe synthetic test fixtures designed for rapid live hackathon presentation:
            </p>

            <div className="space-y-2.5">
              {samples.map((sample) => {
                const isLoading = loadingSampleId === sample.id;
                return (
                  <button
                    key={sample.id}
                    onClick={() => handleLoadSample(sample.id)}
                    disabled={isLoading || loading}
                    className="w-full text-left p-3 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 hover:border-cyan-800/80 transition group"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-xs text-white group-hover:text-cyan-300 transition">
                        {sample.display_name}
                      </span>
                      <RiskBadge severity={sample.expected_severity} size="sm" />
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">{sample.description}</p>
                    {isLoading && (
                      <span className="text-[10px] text-cyan-400 font-mono flex items-center gap-1 mt-1">
                        <RefreshCw className="w-3 h-3 animate-spin" /> Ingesting sample...
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400 flex items-center gap-1">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>Guaranteed zero-harm synthetic test files.</span>
          </div>
        </div>
      </div>

      {/* Analysis Results View */}
      {investigation && (
        <div className="space-y-6 pt-4 animate-in fade-in duration-200">
          {/* Header Card */}
          <div className="rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <div className="flex flex-wrap items-center gap-2 mb-1.5">
                  <span className="text-xs font-mono text-cyan-400 font-bold">{investigation.id}</span>
                  {investigation.is_synthetic_sample && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/40 font-semibold">
                      SYNTHETIC DEMO DATA
                    </span>
                  )}
                  {investigation.quarantine_status === 'QUARANTINED' && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-500/20 text-rose-300 border border-rose-500/40 font-semibold">
                      SIMULATED QUARANTINE ACTIVE
                    </span>
                  )}
                  <span className="text-xs text-slate-400 flex items-center gap-1">
                    <Clock className="w-3 h-3 text-slate-500" />
                    {new Date(investigation.created_at).toLocaleString()}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
                  <span>{investigation.original_filename}</span>
                </h2>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => onNavigateToStory(investigation.id)}
                  className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold transition"
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>Attachment Threat Story</span>
                </button>
                <button
                  onClick={() => setIsSandboxOpen(true)}
                  className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-purple-950 hover:bg-purple-900 text-purple-200 border border-purple-800 text-xs font-medium transition"
                >
                  <Cpu className="w-3.5 h-3.5 text-purple-400" />
                  <span>Import Sandbox Report</span>
                </button>
                <button
                  onClick={() => setIsQuarantineOpen(true)}
                  className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition"
                >
                  <Lock className="w-3.5 h-3.5 text-amber-400" />
                  <span>{investigation.quarantine_status === 'QUARANTINED' ? 'Restore Item' : 'Simulate Quarantine'}</span>
                </button>
                <a
                  href={getExportJsonUrl(investigation.id)}
                  download
                  className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium transition"
                  title="Download Full JSON Report"
                >
                  <Download className="w-4 h-4" />
                </a>
              </div>
            </div>

            {/* Quick Metadata Row */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-4 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                <span className="text-slate-400 text-[10px] uppercase block">Detected Format</span>
                <span className="text-white font-medium">{investigation.detected_format}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80">
                <span className="text-slate-400 text-[10px] uppercase block">File Size</span>
                <span className="text-white font-medium">{(investigation.file_size / 1024).toFixed(1)} KB ({investigation.file_size} B)</span>
              </div>
              <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800/80 col-span-2">
                <span className="text-slate-400 text-[10px] uppercase block">SHA-256 Hash</span>
                <span className="text-cyan-400 truncate block">{investigation.sha256}</span>
              </div>
            </div>
          </div>

          {/* Explainable Risk Score Card */}
          <div className="rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 pb-6 border-b border-slate-800">
              <div className="flex items-center gap-5">
                <div
                  className={`w-20 h-20 rounded-2xl flex flex-col items-center justify-center font-mono font-black border shadow-2xl ${
                    investigation.severity === 'CRITICAL'
                      ? 'bg-rose-950/80 text-rose-400 border-rose-700/80 shadow-rose-900/30'
                      : investigation.severity === 'HIGH'
                      ? 'bg-orange-950/80 text-orange-400 border-orange-700/80 shadow-orange-900/30'
                      : investigation.severity === 'MEDIUM'
                      ? 'bg-amber-950/80 text-amber-400 border-amber-700/80 shadow-amber-900/30'
                      : 'bg-emerald-950/80 text-emerald-400 border-emerald-700/80 shadow-emerald-900/30'
                  }`}
                >
                  <span className="text-3xl leading-none">{investigation.risk_score}</span>
                  <span className="text-[10px] font-sans font-semibold tracking-wider uppercase opacity-75">/ 100</span>
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <RiskBadge severity={investigation.severity} size="lg" />
                    <span className="text-xs font-mono text-slate-400">Deterministic Score</span>
                  </div>
                  <h3 className="text-base font-bold text-white">{investigation.verdict}</h3>
                  <p className="text-xs text-slate-300 mt-1 max-w-xl">
                    {investigation.risk_evaluation?.summary ||
                      'Risk calculated via bounded static signature inspection and weighted rule contributions.'}
                  </p>
                </div>
              </div>

              {/* Scoring Formula Box */}
              {investigation.risk_evaluation?.scoring_breakdown && (
                <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-mono max-w-sm">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-1 font-semibold">
                    Explainable Scoring Math:
                  </div>
                  <div className="text-cyan-300 text-[11px] leading-relaxed">
                    {investigation.risk_evaluation.scoring_breakdown.formula}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-1">
                    Rules Triggered: <span className="text-white">{investigation.findings.length}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Static Detection Findings Breakdown */}
            <div className="mt-6">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
                Static Detection Findings & Rule Contributions ({investigation.findings.length})
              </h3>

              {investigation.findings.length === 0 ? (
                <div className="p-6 rounded-xl bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 text-xs flex items-center gap-3">
                  <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
                  <div>
                    <span className="font-semibold block">No Suspicious Indicators Detected</span>
                    All static checks passed cleanly. Note: A low score indicates zero known signatures matched, but does not guarantee the file is harmless.
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  {investigation.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition space-y-2 text-xs"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-[11px] text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">
                            {f.rule_id}
                          </span>
                          <span className="font-bold text-white text-sm">{f.title}</span>
                          <RiskBadge severity={f.severity} size="sm" />
                        </div>
                        <div className="text-right sm:text-right font-mono text-[11px] text-amber-400">
                          Score Contribution: <strong className="text-white">+{f.contribution} pts</strong>
                        </div>
                      </div>

                      <p className="text-slate-300 leading-relaxed font-sans">{f.explanation}</p>

                      {f.evidence && (
                        <div className="p-2 rounded bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-cyan-300">
                          <span className="text-slate-500 block text-[10px] uppercase font-sans">Observed Evidence:</span>
                          {f.evidence}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* SOC Recommendations */}
            {investigation.risk_evaluation?.recommendations && (
              <div className="mt-6 pt-5 border-t border-slate-800">
                <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">
                  Recommended SOC Playbook Actions
                </h3>
                <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  {investigation.risk_evaluation.recommendations.map((rec, idx) => (
                    <li
                      key={idx}
                      className="p-3 rounded-lg bg-slate-900/70 border border-slate-800/80 text-slate-300 flex items-start gap-2"
                    >
                      <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Modals */}
      {investigation && (
        <>
          <QuarantineModal
            investigation={investigation}
            isOpen={isQuarantineOpen}
            onClose={() => setIsQuarantineOpen(false)}
            onSuccess={(updated) => setInvestigation(updated)}
          />
          <SandboxImportModal
            investigation={investigation}
            isOpen={isSandboxOpen}
            onClose={() => setIsSandboxOpen(false)}
            onSuccess={(updated) => setInvestigation(updated)}
          />
        </>
      )}
    </div>
  );
};
