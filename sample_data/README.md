# SecureMailAnalyzer — Sample Test Fixtures

This directory contains safe, synthetic demonstration files engineered for testing and presenting the **SecureMailAnalyzer** platform.

> **CRITICAL SAFETY GUARANTEE**: None of these files contain live malware, exploits, executable binaries, or destructive payloads. They are structured test fixtures designed to safely trigger static analysis indicators or demonstrate timeline ingestion.

---

## Included Fixtures

### 1. `sample_benign_document.txt`
- **Purpose**: Safe baseline demonstration.
- **Risk Assessment**: `LOW` (Score: 0 / 100).
- **Triggers**: Demonstrates clean file processing, streaming SHA-256 calculation, and clear indicator reporting when zero malicious signatures are found.

### 2. `suspicious_invoice_double_ext.pdf.bat`
- **Purpose**: Demonstrates double-extension detection and deceptive script packaging.
- **Risk Assessment**: `HIGH` / `CRITICAL`.
- **Triggers**:
  - `RULE-DOUBLE-EXT`: File has deceptive naming (`.pdf.bat`).
  - `RULE-SCRIPT-EXT`: File ends in script extension (`.bat`).
  - `RULE-POWERSHELL-FLAGS`: Contains string signatures for hidden PowerShell command execution.

### 3. `suspicious_js_sample.pdf`
- **Purpose**: Demonstrates bounded PDF stream inspection.
- **Risk Assessment**: `MEDIUM` / `HIGH`.
- **Triggers**:
  - `RULE-PDF-OPENACTION`: Automatic trigger `/OpenAction` found in PDF catalog.
  - `RULE-PDF-JAVASCRIPT`: Embedded `/JavaScript` action object detected in bounded inspection.

### 4. `suspicious_macro_sample.docm`
- **Purpose**: Demonstrates safe Office OpenXML archive inspection without extraction.
- **Risk Assessment**: `MEDIUM` / `HIGH`.
- **Triggers**:
  - `RULE-OFFICE-MACRO-CONTAINER`: Detection of `word/vbaProject.bin` inside archive.
  - Safe ZIP inspection without disk extraction or execution risk.

### 5. `synthetic_sandbox_report.json`
- **Purpose**: Demonstrates the Sandbox JSON Import and **Attachment Threat Story** correlation.
- **Contents**: 6 behavioral events across Process Creation, Network Outbound Beacons, File Staging, Registry Persistence (`Run` key), and AMSI evasion.
- **Attribution**: Visually labeled with `[Imported Sandbox Report]` badge to distinguish from directly observed static evidence.
