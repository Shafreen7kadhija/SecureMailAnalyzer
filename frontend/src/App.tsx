import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { OverviewPage } from './pages/OverviewPage';
import { AnalyzePage } from './pages/AnalyzePage';
import { ThreatStoryPage } from './pages/ThreatStoryPage';
import { QuarantinePage } from './pages/QuarantinePage';
import { HistoryPage } from './pages/HistoryPage';
import { ReportsPage } from './pages/ReportsPage';
import { MethodologyPage } from './pages/MethodologyPage';
import { GmailShieldPage } from './pages/GmailShieldPage';
import { fetchDashboardStats, fetchInvestigation } from './services/api';
import { Investigation } from './types';
import { Shield, Lock } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [selectedInvestigationId, setSelectedInvestigationId] = useState<string>('');
  const [activeInvestigation, setActiveInvestigation] = useState<Investigation | null>(null);
  const [quarantinedCount, setQuarantinedCount] = useState<number>(0);

  // Sync dashboard stats
  const refreshStats = () => {
    fetchDashboardStats()
      .then((data) => {
        setQuarantinedCount(data.quarantined_count);
      })
      .catch((err) => console.error('Failed to sync navbar stats', err));
  };

  useEffect(() => {
    refreshStats();
  }, [activeTab]);

  const handleNavigate = (tab: string, investigationId?: string) => {
    if (investigationId) {
      setSelectedInvestigationId(investigationId);
    }
    setActiveTab(tab);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleNavigateToAnalyzeWithRecord = async (investigationId: string) => {
    try {
      const inv = await fetchInvestigation(investigationId);
      setActiveInvestigation(inv);
      setActiveTab('analyze');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      console.error(err);
      setActiveTab('analyze');
    }
  };

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans">
      {/* Top SOC Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        quarantinedCount={quarantinedCount}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        {activeTab === 'overview' && (
          <OverviewPage onNavigate={handleNavigate} />
        )}
        {activeTab === 'gmail-shield' && (
          <GmailShieldPage onNavigateToStory={(id) => handleNavigate('threat-story', id)} />
        )}
        {activeTab === 'analyze' && (
          <AnalyzePage
            onNavigateToStory={(id) => handleNavigate('threat-story', id)}
            initialInvestigation={activeInvestigation}
          />
        )}
        {activeTab === 'threat-story' && (
          <ThreatStoryPage
            initialInvestigationId={selectedInvestigationId}
            onNavigateToAnalyze={() => setActiveTab('analyze')}
          />
        )}
        {activeTab === 'quarantine' && (
          <QuarantinePage
            onNavigateToStory={(id) => handleNavigate('threat-story', id)}
          />
        )}
        {activeTab === 'history' && (
          <HistoryPage
            onNavigateToStory={(id) => handleNavigate('threat-story', id)}
            onNavigateToAnalyze={handleNavigateToAnalyzeWithRecord}
          />
        )}
        {activeTab === 'reports' && (
          <ReportsPage initialInvestigationId={selectedInvestigationId} />
        )}
        {activeTab === 'methodology' && <MethodologyPage />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-[#070a12] py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            <span className="font-semibold text-slate-300">SecureMailAnalyzer</span>
            <span>— Email Attachment Threat Investigation Platform</span>
          </div>
          <div className="flex items-center gap-4 text-[11px] font-mono text-slate-400">
            <span>Windows Localhost (127.0.0.1:5000)</span>
            <span>•</span>
            <span>Safe In-Memory Inspection</span>
            <span>•</span>
            <span className="text-cyan-400">Hackathon Presentation Ready</span>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default App;
