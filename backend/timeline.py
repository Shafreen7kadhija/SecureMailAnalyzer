"""Attachment Threat Story Timeline Generator for SecureMailAnalyzer.
Constructs a chronological, explainable investigation narrative linking
static observations, risk scoring, imported sandbox activity, and analyst actions.
"""

from datetime import datetime, timezone
import uuid
from typing import Any, Dict, List


def generate_initial_threat_story(
    filename: str,
    original_filename: str,
    file_size: int,
    file_extension: str,
    detected_format: str,
    sha256: str,
    findings: List[Dict[str, Any]],
    risk_score: int,
    severity: str,
    verdict: str,
    is_synthetic_sample: bool = False,
) -> List[Dict[str, Any]]:
    """Build the initial chronological Threat Story events for an analyzed attachment."""
    now = datetime.now(timezone.utc)
    base_ts = now.isoformat()
    source_tag = "Synthetic Demo Data" if is_synthetic_sample else "Observed"

    events: List[Dict[str, Any]] = []

    # 1. Submission
    events.append({
        "id": str(uuid.uuid4()),
        "event_type": "FILE_SUBMISSION",
        "title": "Attachment Submitted to SecureMailAnalyzer",
        "description": f"File '{original_filename}' ingested into isolated analysis pipeline. Sanitized internal identifier assigned.",
        "source": "Application Action",
        "severity": "LOW",
        "timestamp": base_ts,
        "details": {
            "original_filename": original_filename,
            "sanitized_name": filename,
            "pipeline": "In-Memory Bounded Static Engine",
        },
    })

    # 2. Metadata Collection
    events.append({
        "id": str(uuid.uuid4()),
        "event_type": "METADATA_EXTRACTED",
        "title": "File Metadata & Physical Attributes Extracted",
        "description": f"Extracted file size ({file_size} bytes / {file_size / 1024:.1f} KB) and declared file extension '{file_extension}'.",
        "source": source_tag,
        "severity": "LOW",
        "timestamp": base_ts,
        "details": {
            "size_bytes": file_size,
            "declared_extension": file_extension,
            "storage_state": "Zero-execution in-memory buffer",
        },
    })

    # 3. SHA-256 Calculation
    events.append({
        "id": str(uuid.uuid4()),
        "event_type": "HASH_CALCULATED",
        "title": "Cryptographic Fingerprint (SHA-256) Generated",
        "description": f"Generated SHA-256 hash: {sha256}. Ready for threat intelligence correlation and endpoint hunting.",
        "source": source_tag,
        "severity": "LOW",
        "timestamp": base_ts,
        "details": {
            "algorithm": "SHA-256 (FIPS 180-4)",
            "sha256": sha256,
        },
    })

    # 4. File Signature Inspection
    events.append({
        "id": str(uuid.uuid4()),
        "event_type": "SIGNATURE_INSPECTED",
        "title": "Magic Byte Signature Inspected",
        "description": f"Analyzed binary file header. Identified underlying structure as: '{detected_format}'.",
        "source": source_tag,
        "severity": "LOW" if not detected_format.startswith("Unknown") else "MEDIUM",
        "timestamp": base_ts,
        "details": {
            "detected_format": detected_format,
            "magic_validation": "Verified against known file format magic signatures",
        },
    })

    # 5. Static Rule Evaluation & Findings
    if findings:
        for idx, f in enumerate(findings):
            events.append({
                "id": str(uuid.uuid4()),
                "event_type": "STATIC_FINDING",
                "title": f"Static Detection: {f.get('title', 'Suspicious Indicator')}",
                "description": f.get("explanation", ""),
                "source": source_tag,
                "severity": f.get("severity", "MEDIUM"),
                "timestamp": base_ts,
                "details": {
                    "rule_id": f.get("rule_id"),
                    "evidence": f.get("evidence"),
                    "base_weight": f.get("weight"),
                    "score_contribution": f.get("contribution"),
                },
            })
    else:
        events.append({
            "id": str(uuid.uuid4()),
            "event_type": "STATIC_CLEAN",
            "title": "Static Inspection: No Suspicious Signatures Triggered",
            "description": "All bounded structural and keyword inspection rules passed without alerting. No active macros or executables detected.",
            "source": source_tag,
            "severity": "LOW",
            "timestamp": base_ts,
            "details": {
                "inspected_rules": "Extension verification, PE signatures, PDF active objects, Office macro container, Shell flags",
                "result": "Zero alerts triggered",
            },
        })

    # 6. Risk Scoring & Assessment
    events.append({
        "id": str(uuid.uuid4()),
        "event_type": "RISK_EVALUATION",
        "title": f"Risk Engine Verdict: {severity} (Score {risk_score}/100)",
        "description": f"Deterministic risk evaluation completed. Assessment verdict: {verdict}.",
        "source": "Application Action",
        "severity": severity,
        "timestamp": base_ts,
        "details": {
            "score": risk_score,
            "severity": severity,
            "verdict": verdict,
            "scoring_model": "Bounded Static Heuristics Engine v1.0",
        },
    })

    return events
