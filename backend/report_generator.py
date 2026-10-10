"""Report Generation Module for SecureMailAnalyzer.
Produces comprehensive JSON and CSV security reports for SOC archival and incident response.
"""

import csv
import io
import json
from typing import Any, Dict


def generate_json_report(investigation: Dict[str, Any]) -> str:
    """Generate detailed structured JSON report."""
    report = {
        "report_metadata": {
            "generator": "SecureMailAnalyzer — Threat Investigation Platform",
            "version": "1.0.0",
            "generated_at": investigation.get("created_at"),
            "report_type": "Attachment Security & Threat Story Assessment",
            "classification": "CONFIDENTIAL // SOC INTERNAL USE",
        },
        "investigation_summary": {
            "investigation_id": investigation.get("id"),
            "original_filename": investigation.get("original_filename"),
            "file_size_bytes": investigation.get("file_size"),
            "file_extension": investigation.get("file_extension"),
            "detected_format": investigation.get("detected_format"),
            "sha256": investigation.get("sha256"),
            "risk_score": investigation.get("risk_score"),
            "severity": investigation.get("severity"),
            "verdict": investigation.get("verdict"),
            "quarantine_status": investigation.get("quarantine_status"),
            "quarantine_notes": investigation.get("quarantine_notes"),
            "is_synthetic_sample": investigation.get("is_synthetic_sample", False),
        },
        "scoring_methodology": {
            "scale": "0 to 100",
            "thresholds": {
                "LOW": "0 - 24",
                "MEDIUM": "25 - 49",
                "HIGH": "50 - 74",
                "CRITICAL": "75 - 100",
            },
            "disclaimer": "Scores represent static heuristic risk and imported sandbox correlation. A Low score does not certify benign safety.",
        },
        "detection_findings": investigation.get("findings", []),
        "timeline_events": [
            {
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "title": e.get("title"),
                "description": e.get("description"),
                "source": e.get("source"),
                "severity": e.get("severity"),
                "details": e.get("details", {}),
            }
            for e in investigation.get("timeline", [])
        ],
        "quarantine_audit_log": investigation.get("quarantine_history", []),
        "analysis_limitations": investigation.get("limitations", []),
    }
    return json.dumps(report, indent=2)


def generate_csv_report(investigation: Dict[str, Any]) -> str:
    """Generate RFC 4180 compliant CSV summary of the investigation."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header section
    writer.writerow(["=== SECUREMAILANALYZER INVESTIGATION SUMMARY ==="])
    writer.writerow(["Investigation ID", investigation.get("id")])
    writer.writerow(["Timestamp", investigation.get("created_at")])
    writer.writerow(["Original Filename", investigation.get("original_filename")])
    writer.writerow(["File Size (Bytes)", investigation.get("file_size")])
    writer.writerow(["Detected Format", investigation.get("detected_format")])
    writer.writerow(["SHA-256 Hash", investigation.get("sha256")])
    writer.writerow(["Risk Score", f"{investigation.get('risk_score')}/100"])
    writer.writerow(["Severity Level", investigation.get("severity")])
    writer.writerow(["Verdict", investigation.get("verdict")])
    writer.writerow(["Quarantine Status", investigation.get("quarantine_status")])
    writer.writerow([])

    # Findings section
    writer.writerow(["=== STATIC DETECTION FINDINGS ==="])
    writer.writerow(["Rule ID", "Title", "Severity", "Weight", "Score Contribution", "Explanation", "Evidence"])
    findings = investigation.get("findings", [])
    if findings:
        for f in findings:
            writer.writerow([
                f.get("rule_id", ""),
                f.get("title", ""),
                f.get("severity", ""),
                f.get("weight", ""),
                f.get("contribution", ""),
                f.get("explanation", ""),
                f.get("evidence", ""),
            ])
    else:
        writer.writerow(["NONE", "No suspicious static indicators detected", "LOW", 0, 0, "All static rules passed cleanly", "N/A"])

    writer.writerow([])

    # Timeline section
    writer.writerow(["=== ATTACHMENT THREAT STORY TIMELINE ==="])
    writer.writerow(["Timestamp", "Source Attribution", "Severity", "Event Title", "Description"])
    timeline = investigation.get("timeline", [])
    for e in timeline:
        writer.writerow([
            e.get("timestamp", ""),
            e.get("source", ""),
            e.get("severity", ""),
            e.get("title", ""),
            e.get("description", ""),
        ])

    return output.getvalue()
