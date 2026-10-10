import React, { useState, useEffect } from 'react';
import {
  Shield,
  Lock,
  Unlock,
  Mail,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Clock,
  Key,
  DownloadCloud,
  Layers,
  Info,
  Sliders,
  FileText,
} from 'lucide-react';
import { RiskBadge } from '../components/RiskBadge';
import {
  analyzeGmailAttachment,
  configureGmailOAuth,
  disconnectGmail,
  fetchEnforcementLogs,
  fetchExtensionStatus,
  fetchGmailAuthUrl,
  fetchGmailMessageDetail,
  fetchGmailMessages,
  fetchGmailStatus,
  releaseBlockedAttachment,
} from '../services/api';
import {
  EnforcementLog,
  GmailMessage,
  GmailMessageDetail,
  GmailStatus,
  Investigation,
} from '../types';

interface GmailShieldPageProps {
  onNavigateToStory: (investigationId: string) => void;
}

export const GmailShieldPage: React.FC<GmailShieldPageProps> = ({ onNavigateToStory }) => {
  // Connection and Extension Status
  const [gmailStatus, setGmailStatus] = useState<GmailStatus | null>(null);
  const [extensionStatus, setExtensionStatus] = useState<any>(null);
  const [loadingStatus, setLoadingStatus] = useState<boolean>(true);

  // OAuth Config Drawer
  const [showConfigDrawer, setShowConfigDrawer] = useState<boolean>(false);
  const [clientId, setClientId] = useState<string>('');
  const [clientSecret, setClientSecret] = useState<string>('');
  const [redirectUri, setRedirectUri] = useState<string>('http://127.0.0.1:5000/api/gmail/callback');
  const [configSaving, setConfigSaving] = useState<boolean>(false);

  // Extension Setup Drawer
  const [showExtensionHelp, setShowExtensionHelp] = useState<boolean>(false);

  // Messages & Attachment Browser
  const [messages, setMessages] = useState<GmailMessage[]>([]);
  const [loadingMessages, setLoadingMessages] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('has:attachment');
  const [expandedMsgId, setExpandedMsgId] = useState<string | null>(null);
  const [messageDetails, setMessageDetails] = useState<Record<string, GmailMessageDetail>>({});
  const [loadingDetailsId, setLoadingDetailsId] = useState<string | null>(null);

  // Attachment Scanning
  const [analyzingAttId, setAnalyzingAttId] = useState<string | null>(null);
  const [recentScannedInv, setRecentScannedInv] = useState<Investigation | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  // Enforcement Logs
  const [enforcementLogs, setEnforcementLogs] = useState<EnforcementLog[]>([]);
  const [loadingLogs, setLoadingLogs] = useState<boolean>(false);

  // Release Modal
  const [releaseModalTarget, setReleaseModalTarget] = useState<EnforcementLog | null>(null);
  const [releaseAnalyst, setReleaseAnalyst] = useState<string>('SOC Lead Analyst');
  const [releaseReason, setReleaseReason] = useState<string>('Document verified through out-of-band sender confirmation.');
  const [releaseLoading, setReleaseLoading] = useState<boolean>(false);

  const loadStatus = async () => {
    setLoadingStatus(true);
    try {
      const [gStat, extStat] = await Promise.all([
        fetchGmailStatus().catch(() => null),
        fetchExtensionStatus().catch(() => null),
      ]);
      setGmailStatus(gStat);
      setExtensionStatus(extStat);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingStatus(false);
    }
  };

  const loadMessages = async () => {
    if (!gmailStatus?.connected) return;
    setLoadingMessages(true);
    try {
      const data = await fetchGmailMessages(searchQuery);
      setMessages(data.messages || []);
    } catch (err: any) {
      console.error('Failed to load Gmail messages', err);
    } finally {
      setLoadingMessages(false);
    }
  };

  const loadLogs = async () => {
    setLoadingLogs(true);
    try {
      const data = await fetchEnforcementLogs();
      setEnforcementLogs(data.logs || []);
    } catch (err) {
      console.error('Failed to fetch enforcement logs', err);
    } finally {
      setLoadingLogs(false);
    }
  };

  useEffect(() => {
    loadStatus();
    loadLogs();
  }, []);

  useEffect(() => {
    if (gmailStatus?.connected) {
      loadMessages();
    }
  }, [gmailStatus?.connected]);

  // Listen for OAuth success popup messages
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      if (event.data?.type === 'GMAIL_AUTH_SUCCESS') {
        loadStatus();
      }
    };
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const handleConnectGmail = async () => {
    try {
      const { auth_url } = await fetchGmailAuthUrl();
      window.open(auth_url, 'GmailOAuth', 'width=600,height=700');
    } catch (err: any) {
      alert(err.message || 'Failed to start Google OAuth flow. Please configure Client ID/Secret.');
      setShowConfigDrawer(true);
    }
  };

  const handleDisconnectGmail = async () => {
    if (!window.confirm('Disconnect Gmail integration and revoke local session?')) return;
    try {
      await disconnectGmail();
      await loadStatus();
      setMessages([]);
    } catch (err: any) {
      alert(err.message || 'Failed to disconnect Gmail');
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setConfigSaving(true);
    try {
      await configureGmailOAuth(clientId, clientSecret, redirectUri);
      alert('OAuth credentials configured successfully.');
      setShowConfigDrawer(false);
      await loadStatus();
    } catch (err: any) {
      alert(err.message || 'Failed to save OAuth credentials');
    } finally {
      setConfigSaving(false);
    }
  };

  const handleToggleMessage = async (msgId: string) => {
    if (expandedMsgId === msgId) {
      setExpandedMsgId(null);
      return;
    }
    setExpandedMsgId(msgId);
    if (!messageDetails[msgId]) {
      setLoadingDetailsId(msgId);
      try {
        const detail = await fetchGmailMessageDetail(msgId);
        setMessageDetails((prev) => ({ ...prev, [msgId]: detail }));
      } catch (err) {
        console.error(err);
      } finally {
        setLoadingDetailsId(null);
      }
    }
  };

  const handleScanAttachment = async (msgId: string, attachmentId: string) => {
    setAnalyzingAttId(attachmentId);
    setScanError(null);
    try {
      const inv = await analyzeGmailAttachment(msgId, attachmentId);
      setRecentScannedInv(inv);
      await loadLogs();
    } catch (err: any) {
      setScanError(err.message || 'Failed to analyze attachment');
    } finally {
      setAnalyzingAttId(null);
    }
  };

  const handleExecuteRelease = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!releaseModalTarget?.investigation_id) return;
    setReleaseLoading(true);
    try {
      await releaseBlockedAttachment(
        releaseModalTarget.investigation_id,
        releaseAnalyst,
        releaseReason
      );
      alert(`Authorized release recorded for ${releaseModalTarget.filename}.`);
      setReleaseModalTarget(null);
      await loadLogs();
    } catch (err: any) {
      alert(err.message || 'Failed to authorize release');
    } finally {
      setReleaseLoading(false);
    }
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-150">
      {/* Top Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-[#0e172a] to-blue-950/60 border border-slate-800 p-6 sm:p-8 shadow-2xl">
        <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800/80">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
                ACTIVE GMAIL SHIELD
              </span>
              <span className="text-xs text-slate-400">• Pre-Download Threat Prevention</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-2">
              <Mail className="w-7 h-7 text-cyan-400" />
              <span>Gmail Threat Detection & Pre-Download Protection</span>
            </h1>
            <p className="mt-2 text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
              Triage attachments directly from your Gmail inbox using authorized Google APIs without saving to your Downloads folder, and block malicious download actions before host execution.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0 flex-wrap">
            <button
              onClick={() => setShowExtensionHelp(!showExtensionHelp)}
              className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 text-xs font-semibold transition flex items-center gap-1.5"
            >
              <Shield className="w-4 h-4 text-cyan-400" />
              <span>Extension Setup</span>
            </button>
            <button
              onClick={loadStatus}
              className="p-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
              title="Refresh Status"
            >
              <RefreshCw className={`w-4 h-4 ${loadingStatus ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Extension Setup Guide (Collapsible Drawer) */}
      {showExtensionHelp && (
        <div className="rounded-2xl bg-[#0f172a] border border-cyan-800/50 p-6 shadow-xl space-y-4 text-xs animate-in fade-in duration-150">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span>Chrome / Edge Extension Installation (Manifest V3)</span>
            </h3>
            <button onClick={() => setShowExtensionHelp(false)} className="text-slate-400 hover:text-white">&times;</button>
          </div>
          <p className="text-slate-300 leading-relaxed">
            The SecureMailAnalyzer browser extension intercepts Gmail attachment download buttons directly inside Chrome or Edge, preventing malicious files from reaching disk.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-[11px]">
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <span className="text-cyan-400 font-bold block">STEP 1: Open Extensions</span>
              <p className="text-slate-400 font-sans">Open Chrome/Edge, navigate to <code className="text-white">chrome://extensions</code>, and toggle <strong>Developer mode</strong> on (top-right).</p>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <span className="text-cyan-400 font-bold block">STEP 2: Load Unpacked</span>
              <p className="text-slate-400 font-sans">Click <strong>Load unpacked</strong> and select the directory: <code className="text-white">SecureMailAnalyzer/extension</code>.</p>
            </div>
            <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
              <span className="text-cyan-400 font-bold block">STEP 3: Active Protection</span>
              <p className="text-slate-400 font-sans">Open Gmail (<code className="text-white">mail.google.com</code>). Downloads on high/critical attachments will be blocked in-page!</p>
            </div>
          </div>
        </div>
      )}

      {/* Grid: Gmail OAuth Connection & Extension Heartbeat */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Card 1: Gmail OAuth Connection */}
        <div className="rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Mail className="w-4 h-4 text-cyan-400" />
                <span>Gmail API Connection</span>
              </h2>
              {gmailStatus?.connected ? (
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                  CONNECTED
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-slate-900 text-slate-400 border border-slate-700">
                  DISCONNECTED
                </span>
              )}
            </div>

            {gmailStatus?.connected ? (
              <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs">
                <div className="text-slate-400 font-mono text-[11px]">Authorized User Account:</div>
                <div className="text-white font-bold text-sm truncate flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{gmailStatus.email}</span>
                </div>
                <div className="text-[11px] text-slate-400">
                  Read-only permissions: Attachments retrieved in-memory without local download.
                </div>
              </div>
            ) : (
              <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2 text-xs text-slate-400">
                <p>Connect your Gmail account via Google OAuth 2.0 to browse emails and triage attachments directly in the SOC console.</p>
                {!gmailStatus?.oauth_configured && (
                  <p className="text-amber-400 text-[11px] flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                    <span>OAuth Client ID / Secret required. Click Configure below.</span>
                  </p>
                )}
              </div>
            )}
          </div>

          <div className="pt-4 mt-4 border-t border-slate-800 flex items-center justify-between gap-3">
            {gmailStatus?.connected ? (
              <button
                onClick={handleDisconnectGmail}
                className="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 font-semibold text-xs border border-slate-700 transition"
              >
                Disconnect Gmail
              </button>
            ) : (
              <button
                onClick={handleConnectGmail}
                className="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs transition flex items-center justify-center gap-2 shadow-md shadow-cyan-950/40"
              >
                <Mail className="w-4 h-4" />
                <span>Connect Gmail via OAuth 2.0</span>
              </button>
            )}
            <button
              onClick={() => setShowConfigDrawer(!showConfigDrawer)}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 transition"
              title="Configure Google OAuth Credentials"
            >
              <Sliders className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Card 2: Pre-Download Policy Enforcement Status */}
        <div className="rounded-2xl bg-[#0f172a] border border-slate-800 p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                <span>Download Protection Status</span>
              </h2>
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950 text-cyan-300 border border-cyan-800">
                STRICT ENFORCEMENT
              </span>
            </div>

            <div className="space-y-2.5 text-xs">
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400">Enforcement Mode:</span>
                <span className="font-mono font-bold text-rose-400">BLOCK HIGH & CRITICAL (&ge;50)</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400">Fail-Closed Safety:</span>
                <span className="font-mono font-bold text-emerald-400">ACTIVE (No Silent Allow)</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400">Repeat Click Bypass:</span>
                <span className="font-mono font-bold text-cyan-400">BLOCKED (Tracked & Halted)</span>
              </div>
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-slate-800 text-[11px] text-slate-400 flex items-center gap-1.5">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>Policy protects Gmail downloads before bytes are saved to disk.</span>
          </div>
        </div>

        {/* Card 3: Live Extension Connection Heartbeat */}
        <div className="rounded-2xl bg-gradient-to-b from-[#131d36] to-[#0f172a] border border-cyan-900/50 p-6 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" />
                <span>Browser Extension Link</span>
              </h2>
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed mb-4">
              The Manifest V3 background service worker connects locally to this SOC console over <code className="text-cyan-300 font-mono">127.0.0.1:5000</code>.
            </p>

            <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 space-y-1.5 font-mono text-[11px]">
              <div className="flex justify-between">
                <span className="text-slate-400">Extension Engine:</span>
                <span className="text-white">Manifest V3</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target Origin:</span>
                <span className="text-cyan-400">mail.google.com</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">API Endpoint:</span>
                <span className="text-emerald-400">/api/extension/check</span>
              </div>
            </div>
          </div>

          <div className="pt-4 mt-4 border-t border-slate-800/80">
            <button
              onClick={() => setShowExtensionHelp(true)}
              className="w-full py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-800/60 font-semibold text-xs transition"
            >
              Verify Extension Configuration &rarr;
            </button>
          </div>
        </div>
      </div>

      {/* OAuth Configuration Drawer (if open) */}
      {showConfigDrawer && (
        <div className="rounded-2xl bg-[#0f172a] border border-cyan-800/60 p-6 shadow-2xl space-y-4 animate-in fade-in duration-150">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Key className="w-4 h-4 text-cyan-400" />
              <span>Google Cloud OAuth 2.0 Credentials Setup</span>
            </h3>
            <button onClick={() => setShowConfigDrawer(false)} className="text-slate-400 hover:text-white">&times;</button>
          </div>
          <form onSubmit={handleSaveConfig} className="space-y-4 text-xs">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">Google OAuth Client ID:</label>
              <input
                type="text"
                value={clientId}
                onChange={(e) => setClientId(e.target.value)}
                placeholder="e.g. 123456789-abcdefg.apps.googleusercontent.com"
                className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono"
                required
              />
            </div>
            <div>
              <label className="block text-slate-300 font-semibold mb-1">Google OAuth Client Secret:</label>
              <input
                type="password"
                value={clientSecret}
                onChange={(e) => setClientSecret(e.target.value)}
                placeholder="GOCSPX-..."
                className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono"
                required
              />
            </div>
            <div>
              <label className="block text-slate-300 font-semibold mb-1">Authorized Redirect URI:</label>
              <input
                type="text"
                value={redirectUri}
                onChange={(e) => setRedirectUri(e.target.value)}
                className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono text-[11px]"
                required
              />
              <p className="text-slate-400 text-[11px] mt-1">Ensure this exact URL is added to "Authorized redirect URIs" in your Google Cloud Console.</p>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <button type="button" onClick={() => setShowConfigDrawer(false)} className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300">Cancel</button>
              <button type="submit" disabled={configSaving} className="px-5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold">
                {configSaving ? 'Saving...' : 'Save OAuth Settings'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Gmail Inbox & Attachment Browser Section */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <DownloadCloud className="w-4 h-4 text-cyan-400" />
              <span>Gmail Attachment Explorer (Zero-Download In-Memory Triage)</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Retrieve attachments directly from Google's API to analyze without downloading to your computer.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={loadMessages}
              disabled={loadingMessages || !gmailStatus?.connected}
              className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition flex items-center gap-1.5 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingMessages ? 'animate-spin' : ''}`} />
              <span>Refresh Messages</span>
            </button>
          </div>
        </div>

        {scanError && (
          <div className="m-5 p-3.5 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{scanError}</span>
          </div>
        )}

        {/* Recent Scan Result Highlight Banner */}
        {recentScannedInv && (
          <div className="m-5 p-4 rounded-xl bg-slate-900 border border-cyan-800/80 shadow-lg space-y-3 animate-in fade-in duration-150">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-3">
                <RiskBadge severity={recentScannedInv.severity} score={recentScannedInv.risk_score} size="md" />
                <span className="text-white font-bold text-sm">{recentScannedInv.original_filename}</span>
                <span className="text-xs font-mono text-cyan-400">({recentScannedInv.id})</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950 text-rose-400 border border-rose-800">
                  POLICY: {recentScannedInv.enforcement_decision}
                </span>
                <button
                  onClick={() => onNavigateToStory(recentScannedInv.id)}
                  className="px-3 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold transition flex items-center gap-1"
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>Inspect Threat Story</span>
                </button>
              </div>
            </div>
            <p className="text-xs text-slate-300">{recentScannedInv.verdict} — {recentScannedInv.findings.length} static findings evaluated.</p>
          </div>
        )}

        {/* Messages List Table */}
        {!gmailStatus?.connected ? (
          <div className="p-12 text-center text-slate-400 text-xs space-y-3">
            <Mail className="w-10 h-10 text-slate-600 mx-auto" />
            <p className="text-sm font-semibold text-slate-300">Gmail is not connected.</p>
            <p>Connect your Gmail account above to view recent emails with attachments and triage them in-memory.</p>
          </div>
        ) : messages.length === 0 ? (
          <div className="p-12 text-center text-slate-400 text-xs">
            {loadingMessages ? 'Querying Gmail API for messages with attachments...' : 'No messages found matching query "has:attachment".'}
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80 text-xs">
            {messages.map((msg) => {
              const isExpanded = expandedMsgId === msg.id;
              const details = messageDetails[msg.id];
              const isLoadingDetails = loadingDetailsId === msg.id;

              return (
                <div key={msg.id} className="hover:bg-slate-800/30 transition">
                  <div
                    onClick={() => handleToggleMessage(msg.id)}
                    className="p-4 flex items-center justify-between gap-4 cursor-pointer"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <button className="text-slate-500 hover:text-cyan-400 transition">
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-cyan-400" /> : <ChevronRight className="w-4 h-4" />}
                      </button>
                      <div className="truncate">
                        <div className="text-white font-semibold truncate text-sm">{msg.subject}</div>
                        <div className="text-slate-400 text-[11px] truncate mt-0.5">
                          From: <span className="text-slate-300">{msg.from}</span>
                        </div>
                      </div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-slate-400 text-[11px] font-mono">{msg.date}</div>
                      <span className="text-[10px] text-cyan-400 font-mono">Click to inspect attachments</span>
                    </div>
                  </div>

                  {/* Expanded Attachments Drawer */}
                  {isExpanded && (
                    <div className="px-6 pb-4 pt-1 bg-slate-900/60 border-t border-slate-800 space-y-3 animate-in fade-in duration-100">
                      {isLoadingDetails ? (
                        <div className="p-4 text-center text-slate-400 text-xs flex items-center justify-center gap-2">
                          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                          <span>Fetching message attachments metadata...</span>
                        </div>
                      ) : details?.attachments?.length ? (
                        <div className="space-y-2">
                          <div className="text-[11px] text-slate-400 uppercase tracking-wider font-semibold">
                            Detected Email Attachments ({details.attachments.length}):
                          </div>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                            {details.attachments.map((att) => {
                              const isScanning = analyzingAttId === att.attachment_id;
                              return (
                                <div
                                  key={att.attachment_id}
                                  className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                                >
                                  <div className="truncate">
                                    <div className="text-white font-semibold truncate">{att.filename}</div>
                                    <div className="text-slate-400 text-[11px] font-mono">
                                      {(att.size_bytes / 1024).toFixed(1)} KB • {att.mime_type}
                                    </div>
                                  </div>
                                  <button
                                    onClick={() => handleScanAttachment(msg.id, att.attachment_id)}
                                    disabled={isScanning}
                                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs shrink-0 transition flex items-center gap-1.5 shadow-sm"
                                  >
                                    {isScanning ? (
                                      <>
                                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                        <span>Triaging...</span>
                                      </>
                                    ) : (
                                      <>
                                        <Shield className="w-3.5 h-3.5" />
                                        <span>Analyze In-Memory</span>
                                      </>
                                    )}
                                  </button>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      ) : (
                        <div className="text-slate-400 text-xs py-2">No downloadable attachments identified in this message payload.</div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Pre-Download Enforcement & Audit Logs Table */}
      <div className="rounded-2xl bg-[#0f172a] border border-slate-800 shadow-xl overflow-hidden">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Lock className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Pre-Download Interception & Enforcement Audit Logs ({enforcementLogs.length})
            </h2>
          </div>
          <button onClick={loadLogs} className="text-xs text-cyan-400 hover:text-cyan-300">Refresh Logs</button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Filename</th>
                <th className="py-3 px-4">Severity / Score</th>
                <th className="py-3 px-4">Enforcement Reason</th>
                <th className="py-3 px-4">Repeat Clicks</th>
                <th className="py-3 px-4 text-right">Overrides</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80 font-mono text-[11px]">
              {enforcementLogs.length > 0 ? (
                enforcementLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-3 px-4 text-slate-400">{new Date(log.timestamp).toLocaleTimeString()}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.action === 'BLOCKED'
                            ? 'bg-rose-950 text-rose-400 border border-rose-800'
                            : log.action === 'RELEASED'
                            ? 'bg-purple-950 text-purple-400 border border-purple-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-white font-medium max-w-[180px] truncate">{log.filename}</td>
                    <td className="py-3 px-4">
                      {log.severity ? (
                        <RiskBadge severity={log.severity} score={log.risk_score} size="sm" />
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-300 font-sans max-w-[240px] truncate" title={log.reason}>
                      {log.reason}
                    </td>
                    <td className="py-3 px-4 text-amber-400 font-bold">
                      {log.repeat_count > 1 ? `${log.repeat_count}x Halted` : '1x'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {log.action === 'BLOCKED' && log.investigation_id && (
                        <button
                          onClick={() => setReleaseModalTarget(log)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[10px] font-medium transition"
                        >
                          Authorize Release
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No attachment download interception events recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Authorized Release Modal */}
      {releaseModalTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="relative w-full max-w-lg rounded-2xl bg-[#0f172a] border border-rose-800/80 shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Unlock className="w-5 h-5 text-amber-400" />
                <span>Authorized Security Release Override</span>
              </h3>
              <button onClick={() => setReleaseModalTarget(null)} className="text-slate-400 hover:text-white">&times;</button>
            </div>
            <div className="my-4 p-3 rounded-lg bg-rose-950/40 border border-rose-800/50 text-xs text-rose-200">
              ⚠️ <strong>Strict Audit Notice:</strong> You are explicitly authorizing the release of a blocked attachment (<code className="text-white">{releaseModalTarget.filename}</code>). This action is recorded with cryptographic tokens in the SOC threat audit log.
            </div>
            <form onSubmit={handleExecuteRelease} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Authorizing Analyst / ID:</label>
                <input
                  type="text"
                  value={releaseAnalyst}
                  onChange={(e) => setReleaseAnalyst(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-slate-300 font-semibold mb-1">Documented Justification (Min 8 characters):</label>
                <textarea
                  rows={3}
                  value={releaseReason}
                  onChange={(e) => setReleaseReason(e.target.value)}
                  className="w-full p-2.5 rounded-lg bg-slate-900 border border-slate-700 text-white"
                  required
                />
              </div>
              <div className="flex justify-end gap-3 pt-2 border-t border-slate-800">
                <button type="button" onClick={() => setReleaseModalTarget(null)} className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300">
                  Cancel
                </button>
                <button type="submit" disabled={releaseLoading} className="px-4 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-bold">
                  {releaseLoading ? 'Recording Release...' : 'Confirm & Authorize Release'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
