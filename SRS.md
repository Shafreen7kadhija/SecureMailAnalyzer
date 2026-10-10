# Software Requirements Specification (SRS)
## SecureMailAnalyzer — Secure Email Attachment Analysis & Threat Investigation Platform

**Document Version:** 2.0.0  
**Classification:** Confidential // SOC Technical Specification  
**System Name:** SecureMailAnalyzer (SMA) with Gmail Shield  
**Date:** October 2026  

---

## 1. Abstract

Email remains the predominant enterprise threat vector for malware delivery, credential theft, and ransomware initiation. Traditional boundary mail filters rely on opaque binary heuristics and scan files post-download, creating a dangerous exposure window where dangerous payloads reach endpoint disks before inspection. 

This Software Requirements Specification (SRS) establishes the technical requirements, architecture, deterministic risk framework, and security boundaries for **SecureMailAnalyzer**. The system ingests email attachments both via direct upload and authorized zero-download Gmail API integration (`gmail.readonly`), performs non-destructive bounded static inspection, computes cryptographic fingerprints, calculates explainable risk scores (0–100), intercepts dangerous download actions pre-download via a Manifest V3 browser extension, enforces fail-closed blocking for High and Critical threats, prevents bypass on repeat attempts, provides an auditable override release workflow, imports external dynamic sandbox telemetry without local execution, constructs a chronological **Attachment Threat Story**, and manages simulated quarantine lifecycle states.

---

## 2. Problem Statement & Objectives

### 2.1 Problem Statement
Enterprise security teams and everyday knowledge workers encounter four fundamental challenges during email attachment triage:
1. **Post-Download Risk Window:** Traditional antivirus tools inspect files only after they have already been saved to the user's hard drive, allowing immediate execution by distracted users.
2. **Opaque Decisions:** Existing automated email gateways produce risk scores without transparent mathematical attribution or verifiable evidence.
3. **Fragmented Telemetry:** Static file attributes, sandbox dynamic execution trees, and analyst containment decisions are stored across disparate consoles, increasing Mean Time to Respond (MTTR).
4. **Execution Hazards:** Analysts face risks when attempting to inspect attachments without automated containment and bounded resource caps.

### 2.2 System Objectives
- **Zero-Download Gmail Attachment Retrieval:** Retrieve attachment bytes directly into memory via authorized Google OAuth 2.0 / Gmail API calls (`gmail.readonly`) without requiring the user to download files locally first.
- **Pre-Download Interception & Prevention:** Prevent supported Gmail attachment download actions for high-risk files (High >= 50, Critical >= 75) before bytes are saved to disk.
- **Fail-Closed Enforcement:** Enforce fail-closed blocking on unanalyzed, pending, or unreachable attachment requests.
- **Repeat-Click Bypass Prevention:** Continuously block repeated download clicks without bypass and track enforcement attempt counts.
- **Auditable Emergency Release:** Provide an auditable analyst release process with mandatory rationale logging and unique authorization tokens (`REL-...`).
- **Explainable Deterministic Scoring:** Generate a transparent score from 0 to 100 based on documented rule weights and base severity floors.
- **Chronological Threat Narrative:** Provide the **Attachment Threat Story** correlating file intake, static indicators, imported sandbox behavior, and containment actions with strict source provenance badges.
- **Simulated Containment:** Provide a quarantine and restoration simulation with audit tracking that updates live SOC dashboard metrics.
- **Machine-Readable Reporting:** Enable 1-click generation of detailed JSON reports and RFC 4180 compliant CSV summaries.

---

## 3. Scope & Operational Boundaries

### 3.1 In-Scope Capabilities
- Bounded inspection of Windows PE binaries (`MZ`), ELF binaries, PDF documents, Microsoft Office OpenXML/ZIP containers (`vbaProject.bin`), and scripts.
- Detection of deceptive double extensions (`.pdf.bat`, `.docx.exe`) and Unicode Right-to-Left Override (`U+202E`).
- OAuth 2.0 integration with Google Gmail API using minimal read-only scopes.
- In-page Gmail DOM download click interception (attachment cards and preview lightbox).
- Browser Downloads API (`chrome.downloads.onCreated`) secondary fallback cancellation.
- Import and validation of external sandbox JSON execution reports.
- Chronological correlation with provenance attribution (`[Observed]`, `[Imported Sandbox Report]`, `[Synthetic Demo Data]`, `[Application Action]`).
- Metadata-driven quarantine simulation and restoration audit trails.
- Export of JSON and CSV artifacts.

### 3.2 Out-of-Scope (Mandatory Constraints)
- The system shall **never** execute uploaded or retrieved files on the host operating system.
- The system shall **never** request, prompt for, or store a user's Gmail password.
- The system shall **never** initiate outbound network connections to IP addresses or domains identified in imported sandbox reports.
- The system shall **never** extract archives to arbitrary host filesystem directories.
- Third-party commercial threat-intelligence services are non-essential for standalone core functionality.

---

## 4. System Architecture & Data Flow

### 4.1 Architectural Pattern
SecureMailAnalyzer uses a decoupled client-server architecture paired with a Manifest V3 browser extension:
- **Presentation Tier:** React 18, TypeScript, Tailwind CSS, Lucide React, Recharts.
- **Browser Protection Tier:** Chrome/Edge Manifest V3 extension (`content.js` DOM interceptor, `background.js` service worker with `downloads` & `storage` permissions).
- **Application & Analysis Tier:** Python 3.13, Flask 3.1 REST API, bounded static inspection engine, deterministic risk engine, Gmail API client, pre-download enforcement engine.
- **Persistence Tier:** SQLite relational database with ACID compliance, automated migrations, and schema initialization.

### 4.2 Data Flow Pipeline

```
[Gmail Web Client (mail.google.com)]
              │
              ├─► [User Clicks Download Action]
              │         │
              │         ▼
              ├─► [Extension content.js Intercept (Capture Phase)]
              │         │
              │         ▼
              ├─► [HTTP POST /api/extension/check]
              │         │
              │         ├─► If Unscanned: FAIL-CLOSED BLOCKED (Prompt Triage)
              │         ├─► If Score >= 50: BLOCKED (Show Threat Alert Modal)
              │         ├─► If Score < 50: ALLOWED (Download Proceeds)
              │         └─► If Released (REL-...): ALLOWED (Audit Verified)
              │
              ├─► [Fallback: background.js chrome.downloads.onCreated]
              │         └─► chrome.downloads.cancel() if policy violated
              │
[Gmail Shield Console / Direct Upload]
              │
              ▼
[HTTP POST /api/gmail/... /api/analyze]
              │
              ├─► [In-Memory Ingestion & Sanitization]
              │         - Size <= 25 MB
              │         - Safe internal filename generation
              │         - Path traversal prevention
              │
              ├─► [Cryptographic Fingerprinting]
              │         - Streaming SHA-256 computation
              │
              ├─► [In-Memory Static Inspection]
              │         - Magic bytes header analysis
              │         - Extension mismatch checks
              │         - Bounded PDF keyword scanning (/OpenAction, /JS)
              │         - Safe ZIP container scan (vbaProject.bin, zip-slip checks)
              │         - Suspicious string & regex heuristics (PowerShell flags)
              │
              ├─► [Deterministic Risk Engine]
              │         - Severity base floor determination
              │         - Secondary rule contribution calculation
              │         - Capped 0-100 score & playbook recommendations
              │
              ├─► [Enforcement Decision Cache]
              │         - Register enforcement policy (ALLOWED / BLOCKED)
              │
              ├─► [Threat Story Assembly]
              │         - Assemble chronological event timeline
              │         - Apply provenance badges ([Observed] / [Application Action])
              │
              ├─► [SQLite Persistence]
              │         - Save to investigations, timeline_events, enforcement_logs
              │
              ▼
[Interactive SOC Dashboard & Threat Story UI]
```

---

## 5. Functional Requirements

### FR-01: Attachment Ingestion & Sanitization
- **FR-01.1:** System shall accept files via HTTP multipart/form-data.
- **FR-01.2:** System shall enforce a maximum file size limit of 25 MB, rejecting oversized files with HTTP 400.
- **FR-01.3:** System shall sanitize filenames, removing directory traversal characters (`../`, `..\\`), null bytes, and illegal Windows filesystem characters.

### FR-02: Static Inspection & Magic Number Verification
- **FR-02.1:** System shall compute streaming SHA-256 hashes for all ingested files.
- **FR-02.2:** System shall inspect initial header bytes to determine underlying file formats (PE, ELF, PDF, ZIP, OLE2, PNG, JPEG, GIF, Text).
- **FR-02.3:** System shall detect extension vs. signature mismatches (e.g., PE executable masquerading as `.pdf` or `.docx`).
- **FR-02.4:** System shall identify deceptive double extensions and Unicode RTL override characters (`\u202e`).
- **FR-02.5:** System shall inspect PDF content up to 2 MB for `/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, and `/EmbeddedFiles`.
- **FR-02.6:** System shall parse ZIP and Office OpenXML entries in memory to detect `vbaProject.bin` and zip slip traversal without disk extraction.

### FR-03: Explainable Risk Scoring Engine
- **FR-03.1:** System shall compute a deterministic risk score constrained to the range 0 to 100.
- **FR-03.2:** Risk score shall map to defined tiers:
  - `LOW`: 0–24
  - `MEDIUM`: 25–49
  - `HIGH`: 50–74
  - `CRITICAL`: 75–100
- **FR-03.3:** Each triggered rule shall provide Rule ID, Title, Severity, Base Weight, Score Contribution, Explanation, and Evidence Snippet.
- **FR-03.4:** System shall generate tactical SOC response playbooks based on severity and matched indicators.

### FR-04: Attachment Threat Story (Signature Feature)
- **FR-04.1:** System shall construct a chronological timeline linking intake, metadata extraction, cryptographic hashing, static findings, risk evaluation, imported sandbox events, and analyst containment.
- **FR-04.2:** Every timeline event shall be classified with one of four provenance badges:
  - `[Observed]`: Static findings directly extracted by this system.
  - `[Imported Sandbox Report]`: User-supplied sandbox traces; not executed locally.
  - `[Synthetic Demo Data]`: Safe synthetic demonstration test fixtures.
  - `[Application Action]`: Platform actions (intake, hashing, quarantine, release).
- **FR-04.3:** The UI shall provide interactive filtering by source attribution.

### FR-05: Sandbox JSON Report Ingestion
- **FR-05.1:** System shall accept sandbox reports via file upload or JSON text paste.
- **FR-05.2:** System shall validate report schema, category fields (`process_creation`, `network_connection`, `file_modification`, `registry_persistence`, `evasion_activity`), and ISO timestamps.
- **FR-05.3:** System shall safely convert validated events into timeline entries with `[Imported Sandbox Report]` attribution.
- **FR-05.4:** System shall enforce a zero-execution guarantee: no network resolution, process execution, or file writing based on sandbox data.

### FR-06: Quarantine Simulation Center
- **FR-06.1:** System shall support simulated state transitions between `ACTIVE`, `QUARANTINED`, and `RESTORED`.
- **FR-06.2:** System shall record analyst identity, timestamp, and justification notes in an immutable audit log.
- **FR-06.3:** Simulated quarantine actions shall dynamically update live SOC dashboard metrics.
- **FR-06.4:** System shall visibly display disclaimers confirming quarantine operations represent metadata tracking rather than host OS file locking.

### FR-07: Reporting & Export
- **FR-07.1:** System shall export structured JSON reports containing metadata, hash, findings, timeline, and limitations.
- **FR-07.2:** System shall export RFC 4180 compliant CSV summaries suitable for spreadsheets and SIEM ingestion.

### FR-08: Authorized Zero-Download Gmail Attachment Retrieval
- **FR-08.1:** System shall implement standard Google OAuth 2.0 authorization code flow with minimum required scopes (`https://www.googleapis.com/auth/gmail.readonly`).
- **FR-08.2:** System shall securely store access and refresh tokens in the local SQLite database (`gmail_auth` table) and handle token expiration/refresh automatically.
- **FR-08.3:** System shall provide Connect Gmail, Disconnect Gmail, and credential configuration controls in the UI.
- **FR-08.4:** System shall list messages with attachments (`has:attachment`) and retrieve attachment metadata (message ID, attachment ID, sender, subject, filename, size) via authorized Gmail API calls.
- **FR-08.5:** System shall retrieve attachment bytes directly into backend memory without requiring the user to download the file to the endpoint computer, feeding the stream directly to the static analysis engine.
- **FR-08.6:** In-memory Gmail triage results shall automatically create full investigation records, populate the Attachment Threat Story, and register pre-download enforcement policies.

### FR-09: Pre-Download Interception & Enforcement Engine
- **FR-09.1:** Manifest V3 extension shall intercept download clicks on attachment cards and lightbox preview dialogs in Gmail (`mail.google.com`) during the DOM event capture phase.
- **FR-09.2:** Extension service worker shall monitor `chrome.downloads.onCreated` as a secondary defense layer, canceling downloads initiated from Gmail if blocked.
- **FR-09.3:** Pre-download policy engine shall evaluate verdicts:
  - Files with `CRITICAL` or `HIGH` risk (score >= 50) shall be **BLOCKED**.
  - Files with `LOW` or `MEDIUM` risk (score < 50) shall be **ALLOWED**.
  - Unanalyzed or pending files shall be **BLOCKED** under a strict fail-closed policy.
- **FR-09.4:** System shall track repeat download attempts, incrementing attempt counters in `enforcement_logs` and preventing bypass on repeated clicks.
- **FR-09.5:** Extension shall present an in-page SOC Threat Alert modal explaining why the download was blocked (Risk score, severity, matched rules).
- **FR-09.6:** System shall provide an auditable emergency release workflow requiring analyst identity and business justification, issuing a unique `REL-...` token to allow a single controlled download.

---

## 6. Non-Functional Requirements

### NFR-01: Security & Containment
- All network interfaces shall bind to `127.0.0.1` by default.
- Zero-execution principle: No subprocess or shell invocation of submitted or retrieved files.
- Bounded reads: File reads capped at 25 MB; regex keyword evaluation capped at 2 MB.
- Password protection: Passwords shall never be requested, transmitted, or logged.

### NFR-02: Performance & Latency
- Static file analysis for files under 5 MB shall complete within 250 milliseconds.
- Extension policy checks (`/api/extension/check`) shall respond within 50 milliseconds.
- Dashboard metric queries shall execute within 50 milliseconds using SQLite indexation.

### NFR-03: Usability & SOC Aesthetics
- The user interface shall adhere to modern SOC operational aesthetics: dark charcoal/navy background (`#090d16`), restrained cyan accents (`#06b6d4`), high-contrast typography, and accessible severity color coding.
- In-page extension modal shall seamlessly match SOC dark theme while displaying clear visual hierarchy.

### NFR-04: Reliability & Data Persistence
- Database transactions shall ensure referential integrity using SQLite foreign keys and automated database schema migrations on startup.
- Network timeouts or API unavailability between extension and backend shall default to **fail-closed** blocking.

---

## 7. Verification & Test Plan

| Test ID | Category | Objective | Verification Criterion | Status |
| :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Cryptography | Verify SHA-256 calculation | Matches standard SHA-256 test vectors | **PASSED** |
| **TC-02** | Static Engine | Clean text file intake | Score = 0, Severity = LOW, 0 findings | **PASSED** |
| **TC-03** | Boundary Safety | File upload size cap | Rejects files > 25 MB with HTTP 400 | **PASSED** |
| **TC-04** | Detection | Extension vs. magic byte mismatch | Flags PE binary disguised as .pdf as CRITICAL | **PASSED** |
| **TC-05** | Robustness | Malformed archive parsing | Handles corrupted zip files without crashing | **PASSED** |
| **TC-06** | Ingestion | Invalid sandbox JSON | Rejects malformed JSON with descriptive message | **PASSED** |
| **TC-07** | Provenance | Sandbox event attribution | Enforces `[Imported Sandbox Report]` label | **PASSED** |
| **TC-08** | Risk Engine | Score boundaries (0-100) | Validates thresholds (0-24, 25-49, 50-74, 75-100) | **PASSED** |
| **TC-09** | Reporting | Structured JSON export | Generates valid JSON with required metadata | **PASSED** |
| **TC-10** | Reporting | RFC 4180 CSV export | Generates valid CSV with escaped rows | **PASSED** |
| **TC-11** | Containment | Quarantine state lifecycle | Updates status `ACTIVE` -> `QUARANTINED` -> `RESTORED` | **PASSED** |
| **TC-12** | Analytics | Dynamic dashboard KPIs | Metrics derived from real database records | **PASSED** |
| **TC-13** | Input Validation| Path traversal sanitization | Sanitizes `../../` from filename inputs | **PASSED** |
| **TC-14** | Containment | Zero host execution | Proves submitted files are never run on OS | **PASSED** |
| **TC-15** | Gmail Auth | OAuth 2.0 URL generation | Correct Google OAuth URL with `gmail.readonly` scope | **PASSED** |
| **TC-16** | Gmail Auth | Token storage lifecycle | Stores, retrieves, and clears tokens in SQLite | **PASSED** |
| **TC-17** | Policy Engine | High & Critical blocking | Blocks High (>=50) and Critical (>=75) files | **PASSED** |
| **TC-18** | Policy Engine | Low risk allowance | Allows Low (<50) files to proceed | **PASSED** |
| **TC-19** | Policy Engine | Fail-closed unscanned blocking | Unscanned attachment defaults to BLOCKED | **PASSED** |
| **TC-20** | Policy Engine | No filename-only verdict reuse | Different file instances require distinct verification | **PASSED** |
| **TC-21** | Policy Engine | Repeat-click bypass prevention | Repeated attempts increment count & remain BLOCKED | **PASSED** |
| **TC-22** | Enforcement | Authorized release workflow | Issues `REL-...` token, updates audit log, permits download | **PASSED** |
| **TC-23** | Enforcement | Release validation rejection | Invalid/unauthorized release requests rejected | **PASSED** |

---

## 8. Limitations & Operational Boundaries

### 8.1 Limitations
- **Browser Scope:** Manifest V3 extension enforcement protects user interactions within supported Chromium browsers (Google Chrome, Microsoft Edge). It does not intercept downloads initiated from third-party native desktop email clients (e.g., Thunderbird, Windows Mail).
- **DOM Variance:** Gmail's web UI periodically updates class names and element hierarchies. The extension employs resilient multi-selector targeting (`a[href*="attid"]`, `div[role="button"][aria-label*="Download"]`, `div[aria-label*="Télécharger"]`, `div[aria-label*="Descargar"]`), but significant Google DOM refactors may require selector maintenance.
- **Fail-Closed by Design:** If the SecureMailAnalyzer local backend is offline, the browser extension fails closed, halting downloads until connectivity is restored.
- **Static Inspection Boundary:** Static inspection evaluates structural syntax and embedded markers within the first 2 MB of data; packed or encrypted payloads require dynamic behavioral execution.
- **Low Score Disclaimer:** A score in the `LOW` band (0–24) indicates zero recognized static heuristics matched; it does not constitute mathematical proof that a file is benign.

### 8.2 Future Roadmap
- Extension manifest support for Firefox (Manifest V2/V3 parity).
- Integration with local YARA rule compilation engines.
- In-memory OLE2 macro stream de-obfuscation (VBA code tokenization).
- Export to STIX 2.1 / TAXII threat intelligence sharing feeds.
