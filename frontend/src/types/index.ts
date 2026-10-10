export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type EventSource = 'Observed' | 'Imported Sandbox Report' | 'Synthetic Demo Data' | 'Application Action';

export interface Finding {
  rule_id: string;
  title: string;
  severity: SeverityLevel;
  weight: number;
  contribution: number;
  explanation: string;
  evidence: string;
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  source: EventSource;
  severity: SeverityLevel;
  details: Record<string, any>;
  sort_order?: number;
}

export interface QuarantineAuditLog {
  id: string;
  investigation_id: string;
  action: 'QUARANTINED' | 'RESTORED' | 'ACTIVE';
  timestamp: string;
  analyst: string;
  reason: string;
  filename?: string;
  sha256?: string;
  severity?: SeverityLevel;
}

export interface Investigation {
  id: string;
  created_at: string;
  filename: string;
  original_filename: string;
  file_size: number;
  file_extension: string;
  detected_format: string;
  sha256: string;
  risk_score: number;
  severity: SeverityLevel;
  verdict: string;
  quarantine_status: 'ACTIVE' | 'QUARANTINED' | 'RESTORED';
  quarantine_notes?: string;
  quarantine_updated_at?: string;
  findings: Finding[];
  limitations: string[];
  is_synthetic_sample: boolean;
  has_sandbox_report: boolean;
  source_type?: string;
  gmail_message_id?: string;
  gmail_attachment_id?: string;
  gmail_sender?: string;
  gmail_subject?: string;
  enforcement_decision?: string;
  timeline: TimelineEvent[];
  quarantine_history?: QuarantineAuditLog[];
  risk_evaluation?: {
    risk_score: number;
    severity: SeverityLevel;
    verdict: string;
    summary: string;
    scoring_breakdown: {
      base_score: number;
      anchor_severity: string;
      rules_triggered: number;
      formula: string;
    };
    recommendations: string[];
  };
  enforcement?: {
    decision: string;
    reason: string;
    is_blocked: boolean;
  };
}

export interface DashboardStats {
  total_analyzed: number;
  severity_counts: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  quarantined_count: number;
  sandbox_correlated_count: number;
  blocked_downloads_count?: number;
  recent_investigations: Array<{
    id: string;
    created_at: string;
    filename: string;
    sha256: string;
    risk_score: number;
    severity: SeverityLevel;
    quarantine_status: string;
    is_synthetic_sample: boolean;
    source_type?: string;
  }>;
  risk_distribution: Array<{
    name: string;
    count: number;
    severity: SeverityLevel;
    color: string;
  }>;
}

export interface SampleFixture {
  id: string;
  name: string;
  display_name: string;
  description: string;
  size_bytes: number;
  expected_severity: SeverityLevel;
  available: boolean;
}

export interface GmailStatus {
  connected: boolean;
  email: string | null;
  oauth_configured: boolean;
  client_id_prefix?: string | null;
  redirect_uri?: string;
  status_label: string;
  connected_at?: string;
}

export interface GmailMessage {
  id: string;
  threadId?: string;
  subject: string;
  from: string;
  date: string;
  snippet: string;
}

export interface GmailAttachment {
  attachment_id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
}

export interface GmailMessageDetail {
  id: string;
  subject: string;
  sender: string;
  date: string;
  attachments: GmailAttachment[];
  attachment_count: number;
}

export interface EnforcementLog {
  id: string;
  timestamp: string;
  filename: string;
  sha256?: string;
  gmail_message_id?: string;
  gmail_attachment_id?: string;
  investigation_id?: string;
  action: string;
  reason: string;
  risk_score?: number;
  severity?: SeverityLevel;
  repeat_count: number;
}
