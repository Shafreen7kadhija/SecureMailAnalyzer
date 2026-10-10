import {
  DashboardStats,
  EnforcementLog,
  GmailMessage,
  GmailMessageDetail,
  GmailStatus,
  Investigation,
  QuarantineAuditLog,
  SampleFixture,
} from '../types';

const API_BASE = '/api';

export async function fetchHealth(): Promise<{ status: string; service: string }> {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error('Backend health check failed');
  return res.json();
}

export async function fetchDashboardStats(): Promise<DashboardStats> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error('Failed to fetch dashboard statistics');
  return res.json();
}

export async function uploadAndAnalyzeFile(file: File, isSample: boolean = false): Promise<Investigation> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('is_sample', isSample ? 'true' : 'false');

  const res = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    body: formData,
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to analyze attachment');
  }
  return data;
}

export async function fetchSamples(): Promise<SampleFixture[]> {
  const res = await fetch(`${API_BASE}/samples`);
  if (!res.ok) throw new Error('Failed to fetch sample catalog');
  const data = await res.json();
  return data.samples;
}

export async function triggerSampleAnalysis(sampleId: string): Promise<Investigation> {
  const res = await fetch(`${API_BASE}/samples/load/${sampleId}`, {
    method: 'POST',
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to analyze sample fixture');
  }
  return data;
}

export async function fetchSyntheticSandboxJson(): Promise<any> {
  const res = await fetch(`${API_BASE}/samples/synthetic-sandbox`);
  if (!res.ok) throw new Error('Failed to fetch synthetic sandbox data');
  return res.json();
}

export async function fetchInvestigations(
  search: string = '',
  severity: string = '',
  limit: number = 50,
  offset: number = 0
): Promise<{ investigations: any[]; count: number }> {
  const params = new URLSearchParams();
  if (search) params.append('search', search);
  if (severity) params.append('severity', severity);
  params.append('limit', limit.toString());
  params.append('offset', offset.toString());

  const res = await fetch(`${API_BASE}/investigations?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch investigations list');
  return res.json();
}

export async function fetchInvestigation(id: string): Promise<Investigation> {
  const res = await fetch(`${API_BASE}/investigations/${id}`);
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.error || `Failed to fetch investigation ${id}`);
  }
  return res.json();
}

export async function importSandboxReport(
  invId: string,
  data: { jsonPayload?: any; file?: File }
): Promise<{ message: string; investigation: Investigation }> {
  let res: Response;

  if (data.file) {
    const formData = new FormData();
    formData.append('file', data.file);
    res = await fetch(`${API_BASE}/investigations/${invId}/sandbox`, {
      method: 'POST',
      body: formData,
    });
  } else {
    res = await fetch(`${API_BASE}/investigations/${invId}/sandbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data.jsonPayload),
    });
  }

  const result = await res.json();
  if (!res.ok) {
    throw new Error(result.error || 'Failed to import sandbox report');
  }
  return result;
}

export async function updateQuarantineState(
  invId: string,
  status: 'QUARANTINED' | 'RESTORED' | 'ACTIVE',
  notes: string,
  analyst: string = 'SOC Analyst (Active Console)'
): Promise<{ message: string; investigation: Investigation }> {
  const res = await fetch(`${API_BASE}/investigations/${invId}/quarantine`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status, notes, analyst }),
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to update quarantine status');
  }
  return data;
}

export async function fetchQuarantineCenter(): Promise<{ items: any[]; audit_trail: QuarantineAuditLog[] }> {
  const res = await fetch(`${API_BASE}/quarantine`);
  if (!res.ok) throw new Error('Failed to fetch quarantine records');
  return res.json();
}

export function getExportJsonUrl(invId: string): string {
  return `${API_BASE}/investigations/${invId}/export/json`;
}

export function getExportCsvUrl(invId: string): string {
  return `${API_BASE}/investigations/${invId}/export/csv`;
}

// ==========================================
// GMAIL INTEGRATION API
// ==========================================

export async function fetchGmailStatus(): Promise<GmailStatus> {
  const res = await fetch(`${API_BASE}/gmail/status`);
  if (!res.ok) throw new Error('Failed to fetch Gmail status');
  return res.json();
}

export async function fetchGmailAuthUrl(): Promise<{ auth_url: string; state: string }> {
  const res = await fetch(`${API_BASE}/gmail/auth-url`);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to generate OAuth URL');
  return data;
}

export async function configureGmailOAuth(clientId: string, clientSecret: string, redirectUri?: string): Promise<any> {
  const res = await fetch(`${API_BASE}/gmail/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to configure OAuth credentials');
  return data;
}

export async function disconnectGmail(): Promise<any> {
  const res = await fetch(`${API_BASE}/gmail/disconnect`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to disconnect Gmail');
  return res.json();
}

export async function fetchGmailMessages(query: string = 'has:attachment'): Promise<{ messages: GmailMessage[]; count: number }> {
  const res = await fetch(`${API_BASE}/gmail/messages?query=${encodeURIComponent(query)}`);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to list Gmail messages');
  return data;
}

export async function fetchGmailMessageDetail(msgId: string): Promise<GmailMessageDetail> {
  const res = await fetch(`${API_BASE}/gmail/messages/${msgId}`);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to fetch message details');
  return data;
}

export async function analyzeGmailAttachment(msgId: string, attachmentId: string): Promise<Investigation> {
  const res = await fetch(`${API_BASE}/gmail/messages/${msgId}/attachments/${attachmentId}/analyze`, {
    method: 'POST',
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to analyze Gmail attachment');
  return data;
}

// ==========================================
// BROWSER EXTENSION & ENFORCEMENT API
// ==========================================

export async function fetchExtensionStatus(): Promise<any> {
  const res = await fetch(`${API_BASE}/extension/status`);
  if (!res.ok) throw new Error('Failed to fetch extension status');
  return res.json();
}

export async function fetchEnforcementLogs(): Promise<{ logs: EnforcementLog[]; count: number }> {
  const res = await fetch(`${API_BASE}/extension/logs`);
  if (!res.ok) throw new Error('Failed to fetch enforcement logs');
  return res.json();
}

export async function releaseBlockedAttachment(investigationId: string, authorizedBy: string, reason: string): Promise<any> {
  const res = await fetch(`${API_BASE}/extension/release`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      investigation_id: investigationId,
      authorized_by: authorizedBy,
      reason: reason,
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'Failed to release attachment');
  return data;
}
