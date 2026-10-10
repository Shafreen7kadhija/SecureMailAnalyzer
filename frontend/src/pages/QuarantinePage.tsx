import React, { useState, useEffect } from 'react';
import {
  Lock,
  Unlock,
  Shield,
  AlertTriangle,
  Clock,
  CheckCircle,
  FileText,
  RefreshCw,
  Search,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import { QuarantineModal } from '../components/QuarantineModal';
import { fetchInvestigation, fetchQuarantineCenter } from '../services/api';
import { Investigation, QuarantineAuditLog } from '../types';

interface QuarantinePageProps {
  onNavigateToStory: (investigationId: string) => void;
}

export const QuarantinePage: React.FC<QuarantinePageProps> = ({ onNavigateToStory }) => {
  const [quarantinedItems, setQuarantinedItems] = useState<any[]>([]);
  const [auditTrail, setAuditTrail] = useState<QuarantineAuditLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Restore Modal target
  const [selectedForModal, setSelectedForModal] = useState<Investigation | null>(null);
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchQuarantineCenter();
      setQuarantinedItems(data.items);
      setAuditTrail(data.audit_trail);
    } catch (err: any) {
      setError(err.message || 'Failed to fetch quarantine center records');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleOpenRestoreModal = async (invId: string) => {
    try {
      const fullInv = await fetchInvestigation(invId);
      setSelectedForModal(fullInv);
      setIsModalOpen(true);
    } catch (err: any) {
      alert(`Could not load investigation: ${err.message}`);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-150">
      {/* Top Banner */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-amber-950/40 via-slate-900 to-rose-950/40 border border-amber-800/40 shadow-xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">
              SIMULATED WORKFLOW
            </span>
            <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <Lock className="w-5 h-5 text-amber-400" />
              <span>Quarantine Center (Simulated Containment)</span>
            </h1>
          </div>
          <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
            Manage simulated quarantine lifecycle, containment holds, and controlled restoration audit trails for suspicious email attachments.
          </p>
        </div>

        <button
          onClick={loadData}
          disabled={loading}
          className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition self-start md:self-auto"
          title="Refresh Quarantine Records"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-amber-400' : ''}`} />
        </button>
      </div>

      {/* Prominent Mandatory Safety Disclaimer */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-start gap-3 text-xs text-slate-300">
        <Shield className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <strong className="text-cyan-300">Important Operational Safeguard:</strong> This Quarantine Center operates strictly as a <em>metadata simulation</em>. It tracks quarantine actions, records analyst justifications, and updates the Attachment Threat Story without executing, modifying, or moving host operating system binaries.
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Quarantined Attachments Table */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-amber-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Currently Quarantined Attachments ({quarantinedItems.length})
            </h2>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Investigation ID</th>
                <th className="py-3 px-4">Filename</th>
                <th className="py-3 px-4">SHA-256 Hash</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Quarantine Reason / Notes</th>
                <th className="py-3 px-4">Updated At</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {quarantinedItems.length > 0 ? (
                quarantinedItems.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono font-medium text-cyan-400">{item.id}</td>
                    <td className="py-3 px-4 font-medium text-white max-w-[180px] truncate">
                      {item.original_filename || item.filename}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 max-w-[140px] truncate" title={item.sha256}>
                      {item.sha256 ? item.sha256.substring(0, 16) + '...' : 'N/A'}
                    </td>
                    <td className="py-3 px-4">
                      <RiskBadge severity={item.severity} score={item.risk_score} size="sm" />
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-[220px] truncate" title={item.quarantine_notes}>
                      {item.quarantine_notes || 'Quarantined by analyst'}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {item.quarantine_updated_at ? new Date(item.quarantine_updated_at).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <button
                        onClick={() => handleOpenRestoreModal(item.id)}
                        className="px-2.5 py-1 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-800 text-[11px] font-medium transition"
                      >
                        Restore
                      </button>
                      <button
                        onClick={() => onNavigateToStory(item.id)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-medium transition"
                      >
                        Threat Story
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No attachments currently in simulated quarantine.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Quarantine Audit Trail History */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Containment Audit Trail ({auditTrail.length})
            </h2>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Investigation ID</th>
                <th className="py-3 px-4">Analyst</th>
                <th className="py-3 px-4">Reason / Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {auditTrail.length > 0 ? (
                auditTrail.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 font-mono text-slate-400 text-[11px]">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 font-mono">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.action === 'QUARANTINED'
                            ? 'bg-rose-950 text-rose-400 border border-rose-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-cyan-400">{log.investigation_id}</td>
                    <td className="py-3 px-4 text-slate-300">{log.analyst}</td>
                    <td className="py-3 px-4 text-slate-400 max-w-[320px] truncate" title={log.reason}>
                      {log.reason}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500">
                    No quarantine audit events recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal */}
      {selectedForModal && (
        <QuarantineModal
          investigation={selectedForModal}
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          onSuccess={() => {
            loadData();
          }}
        />
      )}
    </div>
  );
};
