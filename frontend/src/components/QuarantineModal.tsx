import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, X, Lock, Unlock } from 'lucide-react';
import { updateQuarantineState } from '../services/api';
import { Investigation } from '../types';

interface QuarantineModalProps {
  investigation: Investigation;
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (updated: Investigation) => void;
}

export const QuarantineModal: React.FC<QuarantineModalProps> = ({
  investigation,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const isQuarantined = investigation.quarantine_status === 'QUARANTINED';
  const targetAction = isQuarantined ? 'RESTORED' : 'QUARANTINED';

  const [notes, setNotes] = useState<string>(
    isQuarantined
      ? 'Attachment reviewed by secondary analyst; approved for controlled release.'
      : 'Suspicious indicators detected during email gateway static triage. Automated simulation hold.'
  );
  const [analyst, setAnalyst] = useState<string>('SOC Lead Analyst');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await updateQuarantineState(investigation.id, targetAction, notes, analyst);
      onSuccess(res.investigation);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to update quarantine state');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="relative w-full max-w-lg rounded-2xl bg-[#0f172a] border border-slate-700 shadow-2xl p-6 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg ${
                targetAction === 'QUARANTINED'
                  ? 'bg-rose-950/80 text-rose-400 border border-rose-800'
                  : 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
              }`}
            >
              {targetAction === 'QUARANTINED' ? <Lock className="w-5 h-5" /> : <Unlock className="w-5 h-5" />}
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight">
                Simulate {targetAction === 'QUARANTINED' ? 'Attachment Quarantine' : 'Quarantine Restoration'}
              </h3>
              <p className="text-xs text-slate-400">Investigation ID: {investigation.id}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Safety Disclaimer Banner */}
        <div className="my-4 p-3 rounded-lg bg-cyan-950/40 border border-cyan-800/40 flex items-start gap-2.5 text-xs text-cyan-200">
          <Shield className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-cyan-300">Quarantine Simulation Notice:</span> This workflow manages metadata and security lifecycle state within the platform. The original file is not executed or moved at the host OS level.
          </div>
        </div>

        {/* Target Details */}
        <div className="mb-4 p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1.5 text-xs font-mono">
          <div className="flex justify-between">
            <span className="text-slate-400">Target File:</span>
            <span className="text-white font-medium">{investigation.original_filename}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">SHA-256:</span>
            <span className="text-cyan-400 truncate max-w-[240px]">{investigation.sha256}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-400">Current Status:</span>
            <span className="text-amber-400 font-semibold">{investigation.quarantine_status}</span>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Action Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-300 font-medium mb-1">Analyst Identity:</label>
            <input
              type="text"
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-500 font-sans"
              required
            />
          </div>

          <div>
            <label className="block text-slate-300 font-medium mb-1">Audit Reason / Justification:</label>
            <textarea
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-cyan-500 font-sans leading-relaxed"
              required
            />
          </div>

          <div className="pt-3 flex items-center justify-end gap-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className={`px-4 py-2 rounded-lg font-semibold transition flex items-center gap-1.5 ${
                targetAction === 'QUARANTINED'
                  ? 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-900/40'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-900/40'
              }`}
            >
              {loading ? (
                <span>Processing...</span>
              ) : (
                <>
                  <CheckCircle className="w-3.5 h-3.5" />
                  <span>Confirm {targetAction === 'QUARANTINED' ? 'Quarantine' : 'Restoration'}</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
