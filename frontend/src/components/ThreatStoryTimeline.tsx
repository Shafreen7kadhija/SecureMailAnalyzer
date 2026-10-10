import React, { useState } from 'react';
import {
  Clock,
  Shield,
  FileSearch,
  Hash,
  Terminal,
  Network,
  Cpu,
  Lock,
  Layers,
  ChevronDown,
  ChevronRight,
  Filter,
  Info,
  Sparkles,
  ExternalLink,
  AlertTriangle,
} from 'lucide-react';
import { EventSource, TimelineEvent } from '../types';
import { RiskBadge } from './RiskBadge';

interface ThreatStoryTimelineProps {
  events: TimelineEvent[];
  filename: string;
  sha256: string;
  onOpenSandboxModal?: () => void;
  onOpenQuarantineModal?: () => void;
}

export const ThreatStoryTimeline: React.FC<ThreatStoryTimelineProps> = ({
  events,
  filename,
  sha256,
  onOpenSandboxModal,
  onOpenQuarantineModal,
}) => {
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const expandAll = () => {
    const all: Record<string, boolean> = {};
    events.forEach((e) => (all[e.id] = true));
    setExpandedIds(all);
  };

  const collapseAll = () => {
    setExpandedIds({});
  };

  const filteredEvents = events.filter((e) => {
    if (sourceFilter === 'ALL') return true;
    return e.source === sourceFilter;
  });

  // Source badges
  const getSourceBadge = (source: EventSource) => {
    switch (source) {
      case 'Observed':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-700/60" title="Directly observed by this application's static inspection engine">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
            Observed
          </span>
        );
      case 'Imported Sandbox Report':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-purple-950/80 text-purple-300 border border-purple-700/60" title="Supplied from external sandbox report; not executed on local host">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
            Imported Sandbox Report
          </span>
        );
      case 'Synthetic Demo Data':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-950/80 text-amber-300 border border-amber-700/60" title="Generated for demonstration fixture">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            Synthetic Demo Data
          </span>
        );
      case 'Application Action':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-700/60" title="Action initiated by SecureMailAnalyzer (scan, quarantine, audit)">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            Application Action
          </span>
        );
      default:
        return null;
    }
  };

  // Event category icon
  const getEventIcon = (type: string, source: EventSource) => {
    if (type.includes('SUBMISSION') || type.includes('METADATA')) return FileSearch;
    if (type.includes('HASH')) return Hash;
    if (type.includes('PROCESS')) return Terminal;
    if (type.includes('NETWORK')) return Network;
    if (type.includes('REGISTRY') || type.includes('PERSISTENCE')) return Lock;
    if (type.includes('QUARANTINE')) return Shield;
    if (source === 'Imported Sandbox Report') return Cpu;
    return Layers;
  };

  return (
    <div className="space-y-6">
      {/* Signature Banner */}
      <div className="rounded-xl p-5 bg-gradient-to-r from-cyan-950/40 via-slate-900 to-blue-950/40 border border-cyan-800/40 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-[10px] font-mono font-bold uppercase tracking-wider">
                Signature Feature
              </span>
              <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                Attachment Threat Story
              </h2>
            </div>
            <p className="mt-1 text-xs text-slate-300 max-w-2xl">
              Chronological investigation timeline fusing directly observed static signatures, cryptographic verification, deterministic risk scoring, imported dynamic sandbox behavior, and analyst quarantine containment.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {onOpenSandboxModal && (
              <button
                onClick={onOpenSandboxModal}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950/80 hover:bg-purple-900 text-purple-200 border border-purple-700/60 text-xs font-medium transition"
              >
                <Cpu className="w-3.5 h-3.5 text-purple-400" />
                <span>Import Sandbox Report</span>
              </button>
            )}
            {onOpenQuarantineModal && (
              <button
                onClick={onOpenQuarantineModal}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition"
              >
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                <span>Simulate Quarantine</span>
              </button>
            )}
          </div>
        </div>

        {/* Provenance Attribution Legend */}
        <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-3 text-xs text-slate-400">
          <span className="font-semibold text-slate-300 flex items-center gap-1">
            <Info className="w-3.5 h-3.5 text-cyan-400" /> Evidence Attribution:
          </span>
          <span className="flex items-center gap-1.5">{getSourceBadge('Observed')} <span className="text-[11px]">Direct Static Inspection</span></span>
          <span className="flex items-center gap-1.5">{getSourceBadge('Imported Sandbox Report')} <span className="text-[11px]">User-Supplied VM Behavior</span></span>
          <span className="flex items-center gap-1.5">{getSourceBadge('Application Action')} <span className="text-[11px]">Platform Engine & Quarantine</span></span>
          <span className="flex items-center gap-1.5">{getSourceBadge('Synthetic Demo Data')} <span className="text-[11px]">Demonstration Fixture</span></span>
        </div>
      </div>

      {/* Filter and control bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-slate-400 flex items-center gap-1 font-medium">
            <Filter className="w-3 h-3 text-cyan-400" /> Filter by Source:
          </span>
          {[
            { id: 'ALL', label: `All Events (${events.length})` },
            { id: 'Observed', label: 'Observed' },
            { id: 'Imported Sandbox Report', label: 'Imported Sandbox' },
            { id: 'Application Action', label: 'Application Actions' },
            { id: 'Synthetic Demo Data', label: 'Synthetic Demo' },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setSourceFilter(tab.id)}
              className={`px-2.5 py-1 rounded text-xs transition ${
                sourceFilter === tab.id
                  ? 'bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            onClick={expandAll}
            className="text-[11px] text-slate-400 hover:text-cyan-400 underline decoration-slate-600 underline-offset-2"
          >
            Expand All
          </button>
          <span className="text-slate-600">•</span>
          <button
            onClick={collapseAll}
            className="text-[11px] text-slate-400 hover:text-cyan-400 underline decoration-slate-600 underline-offset-2"
          >
            Collapse All
          </button>
        </div>
      </div>

      {/* Timeline items */}
      <div className="relative pl-6 sm:pl-8 space-y-6 before:absolute before:left-3 sm:before:left-4 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-cyan-500 before:via-blue-600 before:to-slate-800">
        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center bg-slate-900/60 rounded-xl border border-slate-800 text-slate-400 text-sm">
            No events match the selected source filter.
          </div>
        ) : (
          filteredEvents.map((event, index) => {
            const Icon = getEventIcon(event.event_type, event.source);
            const isExpanded = !!expandedIds[event.id];
            const hasDetails = event.details && Object.keys(event.details).length > 0;

            const nodeColors = {
              CRITICAL: 'ring-rose-500 bg-rose-950 text-rose-400 shadow-rose-900/40',
              HIGH: 'ring-orange-500 bg-orange-950 text-orange-400 shadow-orange-900/40',
              MEDIUM: 'ring-amber-500 bg-amber-950 text-amber-400 shadow-amber-900/40',
              LOW: 'ring-cyan-500 bg-slate-900 text-cyan-400 shadow-cyan-900/40',
            }[event.severity] || 'ring-slate-600 bg-slate-900 text-slate-400';

            return (
              <div key={event.id || index} className="relative group">
                {/* Connector Node */}
                <div
                  className={`absolute -left-6 sm:-left-8 top-3.5 w-6 h-6 rounded-full ring-2 ${nodeColors} flex items-center justify-center shadow-lg transition-transform group-hover:scale-110 z-10`}
                >
                  <Icon className="w-3 h-3" />
                </div>

                {/* Event Card */}
                <div
                  className={`rounded-xl border transition-all ${
                    event.severity === 'CRITICAL'
                      ? 'bg-[#12101e] border-rose-900/50 hover:border-rose-700/80 shadow-rose-950/20'
                      : event.severity === 'HIGH'
                      ? 'bg-[#151320] border-orange-900/50 hover:border-orange-700/80 shadow-orange-950/20'
                      : event.source === 'Imported Sandbox Report'
                      ? 'bg-[#121427] border-purple-900/50 hover:border-purple-700/80 shadow-purple-950/20'
                      : 'bg-[#0f172a] border-slate-800 hover:border-slate-700 shadow-slate-950/20'
                  } shadow-md p-4 sm:p-5`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                    <div className="flex-1">
                      <div className="flex flex-wrap items-center gap-2 mb-1.5">
                        {getSourceBadge(event.source)}
                        <RiskBadge severity={event.severity} size="sm" />
                        <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                          <Clock className="w-3 h-3 text-slate-500" />
                          {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'N/A'}
                        </span>
                      </div>
                      <h3 className="text-sm font-semibold text-white tracking-tight flex items-center gap-1.5">
                        {event.title}
                      </h3>
                      <p className="mt-1 text-xs text-slate-300 leading-relaxed">{event.description}</p>
                    </div>

                    {hasDetails && (
                      <button
                        onClick={() => toggleExpand(event.id)}
                        className="self-start sm:self-center flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                      >
                        {isExpanded ? (
                          <>
                            <span>Hide Details</span>
                            <ChevronDown className="w-3 h-3 text-slate-400" />
                          </>
                        ) : (
                          <>
                            <span>View Details</span>
                            <ChevronRight className="w-3 h-3 text-slate-400" />
                          </>
                        )}
                      </button>
                    )}
                  </div>

                  {/* Expandable Technical Details View */}
                  {hasDetails && isExpanded && (
                    <div className="mt-4 pt-3 border-t border-slate-800/80 text-xs font-mono space-y-2 bg-slate-950/60 p-3.5 rounded-lg border border-slate-800">
                      <div className="text-[11px] text-slate-400 uppercase tracking-wider font-sans font-semibold mb-1 flex items-center gap-1">
                        <Terminal className="w-3 h-3 text-cyan-400" /> Technical Telemetry & Evidence:
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
                        {Object.entries(event.details).map(([key, val]) => (
                          <div key={key} className="break-all bg-slate-900/80 p-2 rounded border border-slate-800/60">
                            <span className="text-cyan-400 font-semibold block text-[10px] uppercase">{key.replace(/_/g, ' ')}:</span>
                            <span className="text-slate-200 text-xs">
                              {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
