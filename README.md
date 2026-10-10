# SecureMailAnalyzer — Secure Email Attachment Analysis & Threat Investigation Platform

[![Python](https://img.shields.io/badge/Python-3.13-blue.svg)](https://python.org)
[![React](https://img.shields.io/badge/React-18-cyan.svg)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org)
[![Vite](https://img.shields.io/badge/Vite-6.1-purple.svg)](https://vitejs.dev)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-3.4-teal.svg)](https://tailwindcss.com)
[![Tests](https://img.shields.io/badge/Tests-33%2F33%20Passing-brightgreen.svg)]()

> **Cybersecurity Hackathon 2026 Presentation Showcase**  
> *Zero-Download Gmail Attachment Threat Detection, Pre-Download Protection & Chronological Threat Story Reconstruction*

---

## 1. Problem Statement & Executive Overview

Email attachments remain the primary initial access vector for ransomware, trojans, credential stealers, and business email compromise (BEC). Traditional endpoint anti-virus and secure email gateways suffer from two catastrophic operational gaps:
1. **Post-Download Vulnerability:** Traditional AV only scans files *after* they hit the user's local disk, creating a dangerous race condition where users open or execute malicious files immediately upon download.
2. **Opaque Decisions & Disconnected Evidence:** Gateways produce binary "Blocked" verdicts without explainable attribution, forcing analysts to manually correlate static hashes, dynamic sandbox events, and containment logs across disconnected consoles.

**SecureMailAnalyzer** solves both problems with an end-to-end prevention and investigation platform:
- **Pre-Download Protection in Gmail:** Intercepts attachment downloads *before* bytes reach the endpoint disk using a dual-layer Manifest V3 browser extension and backend policy enforcement.
- **Zero-Download Gmail Attachment Retrieval:** Pulls attachments directly from the Gmail API (`gmail.readonly`) into backend memory without requiring the user to download them to their PC.
- **Explainable Deterministic Scoring (0–100):** Transparent mathematical scoring based on static header inspection, double extension checks, script heuristics, and Office macro containers.
- **Attachment Threat Story (Signature Differentiator):** An explainable chronological investigation timeline linking intake, cryptographic verification, static heuristics, imported sandbox behavioral telemetry, and analyst containment actions.

Every piece of evidence features explicit provenance badges:
- `[Observed]`: Directly extracted by this application's static inspection engine.
- `[Imported Sandbox Report]`: Telemetry imported from external sandbox runs without host execution.
- `[Synthetic Demo Data]`: Pre-packaged safe demonstration test fixtures.
- `[Application Action]`: Actions executed by SecureMailAnalyzer (quarantine, restoration, hashing, release).

---

## 2. Core Features & Capabilities

### 🛡️ Pre-Download Protection & Prevention (Gmail Shield)
- **Zero-Download Triage:** Analyzes Gmail attachments in backend RAM via authorized Gmail API requests; zero dangerous bytes reach the endpoint.
- **Dual-Layer Interception:**
  1. *Layer 1 (DOM Capture Phase):* Intercepts download clicks on Gmail attachment cards and lightbox preview action bars before Gmail's download handlers run.
  2. *Layer 2 (Browser Downloads API):* Fallback defense-in-depth listener (`chrome.downloads.onCreated`) that cancels (`chrome.downloads.cancel`) downloads originating from Gmail if unanalyzed or blocked.
- **Fail-Closed Policy:** Any unanalyzed, pending, or unreachable attachment request is **BLOCKED** by default. Downloads are never permitted on an unknown verdict.
- **Repeat-Click Bypass Prevention:** Repeated clicking on a blocked attachment is tracked by an enforcement counter and blocked continuously without bypass.
- **Auditable Emergency Release:** Blocked files can only be released with an explicit analyst authorization token (`REL-...`), recorded with analyst identity, target filename, and business justification in an immutable audit log.

### 🔍 Static File Inspection & Risk Scoring
- **Header & Magic Number Verification:** Inspects PE (`MZ`), ELF, PDF (`%PDF-`), ZIP/Office (`PK`), and OLE2 headers.
- **Deceptive Extension Detection:** Flags double extensions (e.g., `.pdf.bat`, `.docx.exe`) and Unicode Right-to-Left Override (`U+202E`).
- **Office & Archive Inspection:** In-memory traversal of ZIP/OOXML archives detecting `vbaProject.bin` and directory traversal (Zip Slip) without disk extraction.
- **Deterministic Risk Scoring (0–100):** 4-tier transparent severity mapping:
  - `LOW`: 0–24 (Routine monitoring)
  - `MEDIUM`: 25–49 (Cautious review)
  - `HIGH`: 50–74 (**BLOCKED** by pre-download policy)
  - `CRITICAL`: 75–100 (**BLOCKED** by pre-download policy)

### ⚡ Attachment Threat Story (Signature Differentiator)
- Chronological timeline reconstructing the full incident narrative from intake to containment.
- Ingests external sandbox JSON reports (process trees, network beacons, file drops, registry persistence) with zero local host execution.
- Source filter toggles allowing analysts to isolate directly observed findings from imported telemetry.

### 🔒 Quarantine Simulation & Audit Center
- Metadata-driven lifecycle transitions (`ACTIVE` ↔ `QUARANTINED` ↔ `RESTORED`).
- Analyst audit log recording timestamps, rationale, and updating live SOC dashboard metrics.

### 📊 Reports & SOC Dashboard
- Live metrics, risk distribution charts (Recharts), and recent investigations backed by SQLite.
- 1-click export of structured JSON reports and RFC 4180 CSV incident summaries.

---

## 3. Architecture & Data Flow

```
+--------------------------------------------------------------------------------------------------+
|                                    User Browser / Workspace                                     |
|                                                                                                  |
|   +---------------------------------------+    +----------------------------------------------+  |
|   |          mail.google.com              |    |       SOC Dashboard (React 18 + TS)          |  |
|   |  - Gmail UI with Attachment Cards     |    |   http://127.0.0.1:5000                      |  |
|   |  - content.js (Capture-phase listener)|    |  - Overview KPIs & Recharts                  |  |
|   |  - In-Page SOC Alert Modal            |    |  - Analyze Attachment & 1-Click Fixtures    |  |
|   +---------------------------------------+    |  - Gmail Shield Console & Enforcement Logs   |  |
|                       |                        |  - Attachment Threat Story                   |  |
|                       | Intercept Click        |  - Quarantine Center & Security Reports      |  |
|                       v                        +----------------------------------------------+  |
|   +---------------------------------------+                           |                          |
|   |   Manifest V3 Extension Engine        |                           |                          |
|   |  - background.js (Service Worker)     |                           | REST API Calls           |
|   |  - chrome.downloads.cancel listener   |                           |                          |
|   +---------------------------------------+                           |                          |
+-----------------------------------|-----------------------------------|--------------------------+
                                    | Policy Check / Release            |
                                    v                                   v
+--------------------------------------------------------------------------------------------------+
|                              Flask Backend Server (127.0.0.1:5000)                               |
|                                                                                                  |
|  +--------------------+   +-----------------------+   +----------------------+   +-------------+ |
|  | gmail_service.py   |   | enforcement_engine.py |   | analyzer.py          |   | timeline.py | |
|  | - OAuth 2.0 flow   |   | - Fail-closed policy  |   | - Magic bytes verify |   | - Threat    | |
|  | - gmail.readonly   |   | - Block High/Critical |   | - Bounded scan (2MB) |   |   Story     | |
|  | - In-memory stream |   | - Repeat click track  |   | - Streaming SHA-256  |   | - Badges    | |
|  |   zero-download    |   | - Auditable override  |   | - Macro & double-ext |   |   provenance| |
|  +--------------------+   +-----------------------+   +----------------------+   +-------------+ |
|            |                          |                              |                         | |
|            +--------------------------+------------------------------+-------------------------+ |
|                                       | Database Operations                                      |
|                                       v                                                          |
|                    +------------------------------------------------------+                      |
|                    |             SQLite 3 Database (Local)                |                      |
|                    | - investigations         - timeline_events           |                      |
|                    | - quarantine_logs        - gmail_auth                |                      |
|                    | - enforcement_logs       - release_authorizations    |                      |
|                    +------------------------------------------------------+                      |
+--------------------------------------------------------------------------------------------------+
```

---

## 4. Prerequisites & Installation on Windows

### Prerequisites
1. **Python 3.10+** (Tested on Python 3.13.2)
2. **Node.js 18+ & npm** (Tested on Node.js v22.18.0 & npm 10.9.3)
3. **Google Chrome** or **Microsoft Edge** (for Manifest V3 extension)
4. Windows PowerShell or Command Prompt

### Step 1: Install Backend Dependencies
```powershell
cd c:\Users\shafr\OneDrive\Desktop\SecureMailAnalyzer
python -m pip install -r backend/requirements.txt
```

### Step 2: Build Frontend Production Assets
```powershell
cd frontend
npm install
npm run build
cd ..
```

---

## 5. Google Cloud OAuth & Extension Setup

### Setting Up Google Cloud OAuth (For Live Gmail API)
To retrieve attachments directly from a real Gmail account via the Gmail API:
1. Navigate to the [Google Cloud Console](https://console.cloud.google.com/).
2. Create a project named `SecureMailAnalyzer`.
3. Enable the **Gmail API** under *APIs & Services* > *Library*.
4. Configure the **OAuth Consent Screen**:
   - User Type: **External** (in Testing mode).
   - Add Test Users: Add your test Gmail address.
   - Scopes: Add `https://www.googleapis.com/auth/gmail.readonly` and `https://www.googleapis.com/auth/userinfo.email`.
5. Create **OAuth Client ID** credentials:
   - Application Type: **Web application**.
   - Name: `SecureMailAnalyzer Local`.
   - Authorized redirect URIs: `http://127.0.0.1:5000/api/gmail/callback`.
6. Copy `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` into `backend/.env` (or configure directly in the app via the **Configure Credentials** button on the Gmail Shield page):
   ```env
   GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-client-secret
   GOOGLE_REDIRECT_URI=http://127.0.0.1:5000/api/gmail/callback
   ```

### Loading the Pre-Download Protection Extension in Chrome / Edge
1. Open Google Chrome or Microsoft Edge.
2. Navigate to `chrome://extensions` (Chrome) or `edge://extensions` (Edge).
3. Toggle **Developer mode** on (top-right corner).
4. Click **Load unpacked** (top-left).
5. Select the `extension` directory:
   ```
   c:\Users\shafr\OneDrive\Desktop\SecureMailAnalyzer\extension
   ```
6. The extension **SecureMailAnalyzer — Gmail Shield** is now active with green status!

---

## 6. Launch Instructions

### Run the Unified Server
```powershell
python backend/app.py
```
Open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

The unified server hosts both the REST API and the production-compiled React dashboard on port 5000.

---

## 7. How to Run Automated Tests

Execute the complete 33-test security verification suite:

```powershell
python -m unittest discover -s tests -v
```

### Test Suite Execution Summary (33/33 PASSED)

```
test_01_sha256_calculation ......................................... ok
test_02_benign_text_file_analysis .................................. ok
test_03_upload_size_enforcement .................................... ok
test_04_extension_signature_mismatch ............................... ok
test_05_graceful_handling_malformed_archive ......................... ok
test_06_invalid_sandbox_json_rejection ............................. ok
test_07_valid_sandbox_event_parsing_and_attribution ................ ok
test_08_risk_score_boundaries_and_severity_mapping ................. ok
test_09_json_report_generation ..................................... ok
test_10_csv_export_generation ...................................... ok
test_11_quarantine_simulation_state_changes ........................ ok
test_12_dashboard_statistics ....................................... ok
test_13_missing_investigation_and_error_handling ................... ok
test_14_no_code_execution_guarantee ................................ ok
test_01_oauth_url_generation ....................................... ok
test_02_gmail_token_storage_lifecycle .............................. ok
test_03_high_and_critical_blocked_by_policy ........................ ok
test_04_low_risk_allowed_by_policy ................................. ok
test_05_fail_closed_on_unscanned_attachment ........................ ok
test_06_no_verdict_reuse_by_filename_alone ......................... ok
test_07_repeat_click_bypass_prevention ............................. ok
test_08_authorized_release_workflow ................................ ok
test_09_release_validation_rejection ............................... ok
test_10_identity_matching_compound_keys_and_part_id ................ ok
test_11_filename_only_queries_fail_closed .......................... ok
test_12_oauth_state_generation_and_single_use_validation ........... ok
test_13_release_token_entropy_and_single_use_redemption ............ ok
test_14_api_host_header_validation ................................. ok
test_15_cors_origin_restrictions ................................... ok
test_16_origin_protection_on_sensitive_endpoints ................... ok
test_17_same_filename_different_messages_isolation ................. ok
test_18_release_token_part_id_and_attachment_id_scoping ............ ok
test_19_empty_and_partial_identifiers_fail_closed .................. ok
--------------------------------------------------------------
Ran 33 tests in 0.647s — OK (ALL 33 TESTS PASSED)
```

### What Each Test Verifies

| Test Group | Tests | Coverage |
|---|---|---|
| **Static Engine** | 01–14 (test_backend) | SHA-256, file inspection, risk scoring, quarantine, reports |
| **OAuth Lifecycle** | 01–02 | Token storage, Gmail connection status, disconnect |
| **Enforcement Policy** | 03–09 | Block/allow thresholds, fail-closed, repeat-click, release workflow |
| **Identity Matching** | 10–11, 17, 19 | Compound key lookup, filename-only rejection, same-name isolation, empty ID fail-closed |
| **OAuth CSRF Security** | 12 | State generation, expiry, single-use consumption, replay prevention |
| **Release Token Security** | 13, 18 | 192-bit entropy tokens, part_id/attachment_id scope rejection, single-use redemption |
| **Host/CORS/Origin** | 14–16 | DNS rebinding defense, CORS origin restrictions, state-mutation protection |

---

## 8. Sample Demonstration Fixtures

Pre-configured safe synthetic test files reside in `sample_data/`:

| Fixture Name | Type | Expected Risk | Pre-Download Enforcement | Purpose / Triggered Indicators |
| :--- | :--- | :--- | :--- | :--- |
| `sample_benign_document.txt` | Clean Text | **LOW (0/100)** | **ALLOWED** | Clean baseline test. Zero indicators triggered. |
| `suspicious_invoice_double_ext.pdf.bat` | Script | **CRITICAL (85/100)** | **BLOCKED** | Double extension masquerade + hidden PowerShell flags. |
| `suspicious_macro_sample.docm` | Office Container | **HIGH (65/100)** | **BLOCKED** | In-memory ZIP scan reveals `word/vbaProject.bin`. |
| `suspicious_js_sample.pdf` | PDF Document | **HIGH (60/100)** | **BLOCKED** | Bounded inspection reveals `/OpenAction` & `/JavaScript`. |
| `synthetic_sandbox_report.json` | JSON Telemetry | **MALICIOUS (88)** | N/A (Telemetry) | 6 dynamic events (Process, Network, Persistence). |

> **1-Click Presentation Access**: You do not need to search for files on disk! Click any sample card on the **Analyze Attachment** page or the **Gmail Shield** explorer to trigger instant triage.

---

## 9. Hackathon Presentation Demo Script (3 Minutes)

### [0:00 - 0:45] The Problem: Why Detection Isn't Enough
- **Speaker**: *"Judges, email attachments remain the #1 delivery mechanism for malware and ransomware. But today's endpoint security tools are reactive: files are already downloaded to disk before scanners even run. We built **SecureMailAnalyzer** to change the paradigm from detection to **pre-download prevention**."*
- **Visual**: Show the **Overview** dashboard with live metrics, risk distribution charts, and the **Gmail Shield** navigation tab.

### [0:45 - 1:30] Gmail Pre-Download Protection & Zero-Download Triage
- **Speaker**: *"Through authorized Gmail API integration, SecureMailAnalyzer retrieves and analyzes attachments in memory before a single byte hits the user's hard drive. In Gmail, our browser extension intercepts download clicks in real-time."*
- **Action**: Navigate to **Gmail Shield** tab. Show the extension status indicator (Connected) and the Pre-Download Enforcement Policy (Fail-Closed).
- **Action**: Demonstrate the in-memory analysis of `suspicious_invoice_double_ext.pdf.bat`.
- **Speaker**: *"Notice the verdict: Score 85 — CRITICAL. Our enforcement engine immediately issues a BLOCK. If a user clicks download in Gmail, our extension intercepts the event at the DOM capture phase and blocks the native browser download API. Notice our repeat-click protection: even if the user clicks 10 times, the block count increments and the download remains blocked. It cannot be bypassed."*

### [1:30 - 2:15] Core Differentiator: Attachment Threat Story
- **Action**: Navigate to **Attachment Threat Story**.
- **Speaker**: *"Our signature differentiator is the Attachment Threat Story — an explainable chronological narrative linking intake, cryptographic verification, static heuristics, and containment actions."*
- **Action**: Click **"Import Sandbox Report"** -> Click **"Load & Correlate Demo Sandbox Report Now"**.
- **Speaker**: *"Look at our provenance badges: `[Observed]` for static indicators our engine detected directly, and `[Imported Sandbox Report]` for external sandbox process trees and network beacons. We provide total explainability with zero local malware execution."*

### [2:15 - 3:00] Auditable Release & Reporting
- **Action**: In Gmail Shield, click **"Authorize Release"** on the blocked attachment.
- **Speaker**: *"What if an analyst needs to release a false positive? We require an explicit, auditable release workflow. The analyst enters their ID, notes, and obtains a one-time release token (`REL-...`). Everything is logged to our immutable audit log."*
- **Action**: Navigate to **Security Reports** and download the JSON & CSV reports.
- **Conclusion**: *"SecureMailAnalyzer delivers genuine pre-download prevention, zero-download Gmail triage, and an explainable Threat Story. Thank you!"*

---

## 10. Security Controls, Remediation Summary & Operational Boundaries

### Security Controls Applied (Post Audit Remediation)

| Control | What Was Fixed | Where |
|---|---|---|
| **Attachment Identity Matching** | Binds analysis to exact `message_id`+`attachment_id`+`part_id`+`sha256`. Filename-only queries fail closed. | `database.py: find_investigation_by_identity()` |
| **CORS Restriction** | Restricted to explicit localhost origins + `chrome-extension://*`. No wildcard `*`. | `app.py: CORS(origins=ALLOWED_ORIGINS)` |
| **DNS Rebinding Defense** | Host header validation in `before_request`; rejects any non-localhost Host. | `app.py: setup_if_needed()` |
| **Origin/CSRF Protection** | `verify_origin_protection()` applied on `/quarantine`, `/gmail/config`, `/gmail/disconnect`, `/extension/release`. | `app.py: verify_origin_protection()` |
| **OAuth State CSRF** | Cryptographic state tokens via `secrets.token_urlsafe(32)`, single-use, expire in 10 min, stored in `oauth_states` table. | `database.py: create_oauth_state()`, `validate_and_consume_oauth_state()` |
| **Release Token Entropy** | 192-bit tokens (`REL-{secrets.token_urlsafe(24)}`), 15-min expiry, attachment-scoped, atomic single-use redemption. | `database.py: create_release_authorization()`, `redeem_release_authorization()` |
| **Extension Empty-Filename Bug** | `chrome.downloads.onCreated` no longer matches empty or single-char filenames. Uses URL param matching first. | `extension/background.js` |
| **Service Worker State Loss** | Verdicts cached in `chrome.storage.session` to survive service worker recycles. | `extension/background.js: saveSessionVerdict()` |
| **Extension Compound Cache Keys** | `queryAttachmentPolicy` uses `msg_id::part_id::filename` cache key instead of filename alone. | `extension/background.js: queryAttachmentPolicy()` |
| **Credential Exclusion** | `gmail_credentials.json`, `.env`, `.db.bak` added to `.gitignore`. | `.gitignore` |

### Operational Boundaries

1. **Zero Execution Guarantee**: Uploaded attachments are never executed, passed to subprocesses, or launched in system handlers.
2. **In-Memory Bounded Scanning**: Archives are parsed in memory using Python's `zipfile` without disk extraction. Streams are bounded to 2 MB to prevent decompression bombs.
3. **Fail-Closed Protection**: Any attachment lacking an active valid clean scan is blocked by default. Network timeouts or service unreachability fail safely to BLOCKED.
4. **Credential Isolation**: Google OAuth tokens are stored in the local SQLite database. Passwords are never requested or stored. Minimal read-only scope (`gmail.readonly`) is enforced.
5. **Localhost Binding**: Development server is strictly bound to `127.0.0.1`. Host header validation prevents DNS rebinding attacks.
6. **Input Sanitization**: User-controlled filenames are stripped of path traversal sequences (`../`, null bytes, illegal characters).
7. **Download Interception Accuracy**: The primary pre-download enforcement happens at DOM capture phase via `content.js`. `chrome.downloads.onCreated` is a secondary defense-in-depth layer — it may fire after initial bytes are allocated in a temporary buffer but cancels before transfer completes to disk. It does **not** guarantee zero network bytes.
8. **Scope of Protection**: Pre-download protection covers user clicks on attachment cards, preview dialog download buttons, and browser downloads originating from Gmail. It does not replace enterprise firewall SSL inspection or OS-level kernel file filtering.

