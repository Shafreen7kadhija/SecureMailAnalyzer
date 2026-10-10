import React from 'react';
import { Shield, Activity, Upload, Clock, Lock, FileText, BookOpen, Layers, Mail } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  quarantinedCount?: number;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, quarantinedCount = 0 }) => {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'gmail-shield', label: 'Gmail Shield', icon: Mail, highlight: true },
    { id: 'analyze', label: 'Analyze Attachment', icon: Upload },
    { id: 'threat-story', label: 'Attachment Threat Story', icon: Layers },
    { id: 'quarantine', label: 'Quarantine Center', icon: Lock, badge: quarantinedCount },
    { id: 'history', label: 'Investigation History', icon: Clock },
    { id: 'reports', label: 'Security Reports', icon: FileText },
    { id: 'methodology', label: 'Methodology', icon: BookOpen },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#0c1222]/90 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setActiveTab('overview')}>
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-700 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/40">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-tight text-white text-lg">SecureMail<span className="text-cyan-400">Analyzer</span></span>
                <span className="px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider bg-cyan-950 text-cyan-300 border border-cyan-800/80 rounded">SOC v1.0</span>
              </div>
              <p className="text-[11px] text-slate-400 hidden sm:block">Email Attachment Threat Inspection & Explainable Scoring</p>
            </div>
          </div>

          {/* Nav links */}
          <nav className="hidden md:flex items-center space-x-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                      : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="ml-1 px-1.5 py-0.2 text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40 rounded-full">
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Quick Action Button & Live Status */}
          <div className="flex items-center gap-3">
            <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="text-[11px] font-mono text-emerald-400">127.0.0.1 ACTIVE</span>
            </div>
            <button
              onClick={() => setActiveTab('analyze')}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-semibold text-xs transition shadow-md shadow-cyan-500/15"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>New Analysis</span>
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Nav row */}
      <div className="md:hidden flex overflow-x-auto px-4 py-2 space-x-1 border-t border-slate-800/80 bg-slate-950/80">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-xs whitespace-nowrap ${
                isActive ? 'bg-cyan-500/20 text-cyan-300 font-semibold' : 'text-slate-400'
              }`}
            >
              <Icon className="w-3 h-3" />
              <span>{item.label}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};
