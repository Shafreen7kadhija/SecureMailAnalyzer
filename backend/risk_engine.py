"""Deterministic Risk Scoring Engine for SecureMailAnalyzer.
Calculates an explainable 0-100 risk score with transparent rule contributions,
severity categorization, and actionable SOC recommendations.
"""

from typing import Any, Dict, List, Tuple

# Project-defined risk thresholds
SEVERITY_THRESHOLDS = [
    (75, 100, "CRITICAL", "Immediate containment required. High probability of malicious intent or weaponization."),
    (50, 74, "HIGH", "Strong indicators of deceptive packaging, active content, or weaponization."),
    (25, 49, "MEDIUM", "Suspicious characteristics or macro containers requiring secondary review."),
    (0, 24, "LOW", "No overt static indicators detected within inspected boundaries. Note: Not a guarantee of benign safety."),
]


def map_score_to_severity(score: int) -> Tuple[str, str]:
    """Map a 0-100 score to its severity band and explanation."""
    for min_score, max_score, sev, explanation in SEVERITY_THRESHOLDS:
        if min_score <= score <= max_score:
            return sev, explanation
    return "CRITICAL", "Score exceeds defined bounds."


def generate_recommendations(severity: str, findings: List[Dict[str, Any]]) -> List[str]:
    """Generate prioritized SOC playbook response recommendations based on findings."""
    recommendations = []
    rule_ids = {f.get("rule_id", "") for f in findings}

    if severity == "CRITICAL":
        recommendations.append("Execute immediate simulated or gateway quarantine to prevent user interaction.")
        recommendations.append("Query enterprise EDR for the attachment's SHA-256 hash across all endpoints.")
        recommendations.append("Purge identical message deliveries from email mailboxes tenant-wide.")
        recommendations.append("Block originating sender address, domain, and sending MTA IP at email security perimeter.")
    elif severity == "HIGH":
        recommendations.append("Simulate quarantine and hold message in administrative review queue.")
        recommendations.append("Submit attachment to an isolated dynamic sandbox for automated execution telemetry.")
        recommendations.append("Analyze recipient logs to determine if attachment was opened prior to investigation.")
    elif severity == "MEDIUM":
        recommendations.append("Inspect attachment in isolated analyst workstation before releasing to end recipient.")
        recommendations.append("Check corporate threat intelligence feeds for matching SHA-256 or sender domain reputation.")
        recommendations.append("Verify business legitimacy with the sender via an out-of-band communication channel.")
    else:  # LOW
        recommendations.append("Permit delivery with standard email gateway security headers.")
        recommendations.append("Maintain awareness: Low score verifies absence of known static indicators, not safety proof.")

    # Rule-specific tactical recommendations
    if "RULE-EXT-MISMATCH-EXE" in rule_ids or "RULE-DOUBLE-EXTENSION" in rule_ids:
        recommendations.append("Tactical: File disguises its true file format; alert user awareness team to recent campaign lures.")
    if "RULE-OFFICE-MACRO-CONTAINER" in rule_ids:
        recommendations.append("Tactical: VBA macro project identified; ensure Microsoft Office Attack Surface Reduction (ASR) rules are active.")
    if "RULE-PDF-JAVASCRIPT" in rule_ids or "RULE-PDF-LAUNCH" in rule_ids:
        recommendations.append("Tactical: Embedded active PDF elements detected; disable Acrobat JavaScript execution on endpoint policies.")

    return recommendations


def evaluate_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate findings using a deterministic, transparent scoring formula."""
    if not findings:
        return {
            "risk_score": 0,
            "severity": "LOW",
            "verdict": "BENIGN / NO STATIC INDICATORS FOUND",
            "summary": "No suspicious static indicators detected within inspected boundaries. Attachment displays normal structural characteristics.",
            "annotated_findings": [],
            "scoring_breakdown": {
                "base_score": 0,
                "highest_rule_severity": "NONE",
                "rules_triggered": 0,
                "formula": "Zero static indicators matched -> Score 0 (LOW)",
            },
            "recommendations": generate_recommendations("LOW", []),
        }

    # Count by severity
    crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")

    # Establish severity anchor floor
    if crit_count > 0:
        base_score = 75
        anchor_severity = "CRITICAL"
        # Additional critical findings add +8, high adds +5, medium adds +2, max 100
        extra = (crit_count - 1) * 8 + high_count * 5 + med_count * 2
        raw_score = base_score + extra
    elif high_count > 0:
        base_score = 50
        anchor_severity = "HIGH"
        # Additional high findings add +6, medium adds +3, low adds +1, max 74 unless multiple high push to critical boundary
        extra = (high_count - 1) * 7 + med_count * 4 + low_count * 2
        raw_score = base_score + extra
    elif med_count > 0:
        base_score = 25
        anchor_severity = "MEDIUM"
        extra = (med_count - 1) * 6 + low_count * 3
        raw_score = base_score + extra
    else:
        base_score = 10
        anchor_severity = "LOW"
        extra = (low_count - 1) * 4
        raw_score = base_score + extra

    final_score = min(100, max(0, raw_score))
    severity, verdict_desc = map_score_to_severity(final_score)

    # Compute transparent contribution for each finding
    annotated_findings = []
    total_weights = sum(f.get("weight", 20) for f in findings) or 1
    
    for f in findings:
        item = dict(f)
        # Proportionate attribution of final score to each finding
        fraction = item.get("weight", 20) / total_weights
        calc_contribution = max(1, round(fraction * final_score))
        item["contribution"] = calc_contribution
        annotated_findings.append(item)

    # Verdict wording
    if severity == "CRITICAL":
        verdict = "MALICIOUS / HIGH-CONFIDENCE SUSPICIOUS"
    elif severity == "HIGH":
        verdict = "SUSPICIOUS / ELEVATED RISK"
    elif severity == "MEDIUM":
        verdict = "SUSPICIOUS / NEEDS REVIEW"
    else:
        verdict = "LOW RISK / MINIMAL INDICATORS"

    return {
        "risk_score": final_score,
        "severity": severity,
        "verdict": verdict,
        "summary": verdict_desc,
        "annotated_findings": annotated_findings,
        "scoring_breakdown": {
            "base_score": base_score,
            "anchor_severity": anchor_severity,
            "rules_triggered": len(findings),
            "findings_by_severity": {
                "CRITICAL": crit_count,
                "HIGH": high_count,
                "MEDIUM": med_count,
                "LOW": low_count,
            },
            "formula": f"Base Floor ({base_score} for {anchor_severity}) + Secondary Bonus ({extra}) -> Capped at {final_score}/100",
        },
        "recommendations": generate_recommendations(severity, findings),
    }
