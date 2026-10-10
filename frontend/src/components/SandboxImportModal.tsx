import React, { useState } from 'react';
import { Cpu, Upload, FileText, CheckCircle, AlertTriangle, X, Sparkles } from 'lucide-react';
import { fetchSyntheticSandboxJson, importSandboxReport } from '../services/api';
import { Investigation } from '../types';

interface SandboxImportModalProps {
  investigation: Investigation;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (updated: Investigation) => void;
}

export const SandboxImportModal: React.FC<SandboxImportModalProps> = ({
  investigation,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const [mode, setMode] = useState<'sample' | 'paste' | 'upload'>('sample');
  const [jsonText, setJsonText] = useState<string>('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleLoadSample = async () => {
    setLoading(true);
    setError(null);
    try {
      const sampleData = await fetchSyntheticSandboxJson();
      const res = await importSandboxReport(investigation.id, { jsonPayload: sampleData });
      onSuccess(res.investigation);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to load synthetic sandbox report');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmitCustom = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      if (mode === 'upload' && selectedFile) {
        const res = await importSandboxReport(investigation.id, { file: selectedFile });
        onSuccess(res.investigation);
        onClose();
      } else if (mode === 'paste') {
        let parsed;
        try {
          parsed = JSON.parse(jsonText);
        } catch (e: any) {
          throw new Error(`JSON Syntax Error: ${e.message}`);
        }
        const res = await importSandboxReport(investigation.id, { jsonPayload: parsed });
        onSuccess(res.investigation);
        onClose();
      }
    } catch (err: any) {
      setError(err.message || 'Failed to import sandbox report');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-xl rounded-2xl bg-[#0f172a] border border-slate-700 shadow-2xl p-6 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-950/80 text-purple-400 border border-purple-800">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">Import Dynamic Sandbox Report</h3>
              <p className="text-xs text-slate-400">Correlate behavioral events with static findings</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Safety Disclaimer */}
        <div className="my-4 p-3 rounded-lg bg-purple-950/40 border border-purple-800/40 flex items-start gap-2.5 text-xs text-purple-200">
          <AlertTriangle className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-purple-300">Mandatory Safety Guard:</span> SecureMailAnalyzer never reproduces, executes, or initiates connections to IPs/domains from imported reports. Events are strictly integrated into the Threat Story with clear source attribution.
          </div>
        </div>

        {/* Mode Selector Tabs */}
        <div className="flex border-b border-slate-800 mb-4 text-xs">
          <button
            onClick={() => setMode('sample')}
            className={`px-4 py-2 border-b-2 font-medium transition flex items-center gap-1.5 ${
              mode === 'sample'
                ? 'border-purple-500 text-purple-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span>Load Demo Sandbox (1-Click)</span>
          </button>
          <button
            onClick={() => setMode('paste')}
            className={`px-4 py-2 border-b-2 font-medium transition flex items-center gap-1.5 ${
              mode === 'paste'
                ? 'border-purple-500 text-purple-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Paste JSON Text</span>
          </button>
          <button
            onClick={() => setMode('upload')}
            className={`px-4 py-2 border-b-2 font-medium transition flex items-center gap-1.5 ${
              mode === 'upload'
                ? 'border-purple-500 text-purple-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Upload JSON File</span>
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Tab 1: One-Click Demo Sample */}
        {mode === 'sample' && (
          <div className="space-y-4 text-xs">
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
              <div className="font-semibold text-white flex items-center gap-2">
                <span>Pre-Configured Synthetic Behavioral Report</span>
                <span className="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">SYNTHETIC FIXTURE</span>
              </div>
              <p className="text-slate-300 leading-relaxed">
                Contains 6 multi-stage behavioral events from an emulated Windows 10 sandbox VM:
              </p>
              <ul className="list-disc list-inside space-y-1 text-slate-400 font-mono text-[11px]">
                <li><span className="text-rose-400">Process:</span> Parent cmd.exe spawned hidden PowerShell</li>
                <li><span className="text-orange-400">Network:</span> Outbound HTTP beacon to 198.51.100.24:8443</li>
                <li><span className="text-amber-400">Filesystem:</span> Dropped update_agent_x64.dll into AppData</li>
                <li><span className="text-rose-400">Persistence:</span> Added Run key registry entry</li>
                <li><span className="text-cyan-400">Evasion:</span> VirtualProtect hook on AmsiScanBuffer</li>
              </ul>
            </div>

            <button
              onClick={handleLoadSample}
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-semibold shadow-lg shadow-purple-950/40 transition flex items-center justify-center gap-2"
            >
              <Sparkles className="w-4 h-4 text-amber-300" />
              <span>{loading ? 'Correlating Events...' : 'Load & Correlate Demo Sandbox Report Now'}</span>
            </button>
          </div>
        )}

        {/* Tab 2: Paste JSON */}
        {mode === 'paste' && (
          <form onSubmit={handleSubmitCustom} className="space-y-4 text-xs">
            <div>
              <label className="block text-slate-300 font-medium mb-1">JSON Sandbox Schema:</label>
              <textarea
                rows={8}
                value={jsonText}
                onChange={(e) => setJsonText(e.target.value)}
                placeholder='{\n  "sandbox_metadata": { "analyzer_version": "Cuckoo v4" },\n  "events": [\n    {\n      "category": "process_creation",\n      "event_title": "Spawned process",\n      "severity": "HIGH",\n      "description": "Details here..."\n    }\n  ]\n}'
                className="w-full p-3 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono text-[11px] focus:outline-none focus:border-purple-500"
                required
              />
            </div>
            <div className="flex justify-end gap-3">
              <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300">Cancel</button>
              <button
                type="submit"
                disabled={loading || !jsonText.trim()}
                className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold transition"
              >
                {loading ? 'Importing...' : 'Validate & Import'}
              </button>
            </div>
          </form>
        )}

        {/* Tab 3: Upload JSON */}
        {mode === 'upload' && (
          <form onSubmit={handleSubmitCustom} className="space-y-4 text-xs">
            <div className="border-2 border-dashed border-slate-700 rounded-xl p-6 text-center hover:border-purple-500 transition">
              <Upload className="w-8 h-8 text-slate-500 mx-auto mb-2" />
              <input
                type="file"
                accept=".json"
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                className="block w-full text-slate-400 file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-purple-950 file:text-purple-300 hover:file:bg-purple-900 cursor-pointer"
                required
              />
            </div>
            {selectedFile && (
              <p className="text-slate-300 font-mono text-[11px]">Selected: {selectedFile.name} ({selectedFile.size} bytes)</p>
            )}
            <div className="flex justify-end gap-3">
              <button type="button" onClick={onClose} className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300">Cancel</button>
              <button
                type="submit"
                disabled={loading || !selectedFile}
                className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-semibold transition"
              >
                {loading ? 'Importing...' : 'Upload & Correlate'}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
