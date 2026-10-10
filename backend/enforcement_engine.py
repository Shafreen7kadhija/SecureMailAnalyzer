"""Pre-Download Policy Enforcement Engine for SecureMailAnalyzer.
Evaluates threat verdicts, determines blocking actions, tracks repeat attempts,
and enforces auditable single-use release authorizations.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from database import (
    create_release_authorization,
    find_investigation_by_gmail_attachment,
    find_investigation_by_hash,
    find_investigation_by_identity,
    get_investigation,
    is_attachment_released,
    log_enforcement_event,
    redeem_release_authorization,
)

# Policy Configuration
POLICY_THRESHOLDS = {
    "CRITICAL": {"min_score": 75, "action": "BLOCKED", "description": "Immediate block. Severe threat indicators detected."},
    "HIGH": {"min_score": 50, "action": "BLOCKED", "description": "Pre-download block. Strong weaponization or active script markers."},
    "MEDIUM": {"min_score": 25, "action": "ALLOWED_WITH_CAUTION", "description": "Permitted with prominent security warning. Suspicious structure."},
    "LOW": {"min_score": 0, "action": "ALLOWED", "description": "Permitted under policy. Zero static indicators detected within inspected bounds."},
}


def evaluate_enforcement_decision(
    risk_score: int,
    severity: str,
    sha256: Optional[str] = None,
    investigation_id: Optional[str] = None,
) -> Tuple[str, str, bool]:
    """Evaluate whether an attachment download should be blocked, allowed, or has an active release.
    Returns: (decision: 'BLOCKED' | 'ALLOWED' | 'ALLOWED_WITH_CAUTION' | 'RELEASED', reason, is_blocked)
    """
    # Check for active explicit release authorization
    if is_attachment_released(sha256=sha256, investigation_id=investigation_id):
        return (
            "RELEASED",
            "Download permitted via explicit, auditable authorized security release override.",
            False,
        )

    sev = severity.upper()
    if sev in {"CRITICAL", "HIGH"} or risk_score >= 50:
        return (
            "BLOCKED",
            f"Pre-download blocked by policy. Attachment evaluated as {sev} risk (Score: {risk_score}/100).",
            True,
        )
    elif sev == "MEDIUM" or risk_score >= 25:
        return (
            "ALLOWED_WITH_CAUTION",
            f"Permitted with warning. Attachment evaluated as MEDIUM risk (Score: {risk_score}/100). Exercise caution.",
            False,
        )
    else:
        return (
            "ALLOWED",
            f"Permitted by policy. Attachment evaluated as LOW risk (Score: {risk_score}/100). Note: Not a guarantee of safety.",
            False,
        )


def check_attachment_enforcement_status(
    filename: str,
    sha256: Optional[str] = None,
    gmail_message_id: Optional[str] = None,
    gmail_attachment_id: Optional[str] = None,
    gmail_part_id: Optional[str] = None,
    release_token: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """Check enforcement decision for an attachment request.
    Validates identity by reliable identifiers (message ID, part ID, attachment ID, or SHA-256).
    Fails closed: unanalyzed or untrusted requests return PENDING_ANALYSIS (blocked).
    """
    # Attempt to redeem explicit release token if supplied
    if release_token:
        ok_rel, rel_msg, rel_data = redeem_release_authorization(
            token=release_token,
            gmail_message_id=gmail_message_id,
            gmail_attachment_id=gmail_attachment_id,
            gmail_part_id=gmail_part_id,
            sha256=sha256,
        )
        if ok_rel and rel_data:
            return {
                "status": "RELEASED",
                "enforcement_decision": "RELEASED",
                "is_blocked": False,
                "filename": filename or rel_data.get("filename", "attachment"),
                "reason": f"Authorized release verified: single-use download permitted for {rel_data.get('authorized_by', 'analyst')}.",
                "investigation_id": rel_data.get("investigation_id"),
                "risk_score": None,
                "severity": None,
                "can_release": False,
                "is_released": True,
            }
        else:
            return {
                "status": "RELEASE_REJECTED",
                "enforcement_decision": "BLOCKED",
                "is_blocked": True,
                "filename": filename,
                "reason": f"Release token rejected: {rel_msg}",
                "investigation_id": None,
                "risk_score": None,
                "severity": None,
                "can_release": True,
                "is_released": False,
            }

    # Find investigation by reliable verified identity
    investigation = find_investigation_by_identity(
        gmail_message_id=gmail_message_id,
        gmail_attachment_id=gmail_attachment_id,
        gmail_part_id=gmail_part_id,
        sha256=sha256,
        filename=filename,
    )

    # If unanalyzed or unidentified, fail-closed: do not permit download!
    if not investigation:
        log_enforcement_event(
            filename=filename,
            action="INTERCEPTED_PENDING",
            reason="Download intercepted. Attachment has not completed analysis or identity cannot be verified; pending triage.",
            sha256=sha256,
            gmail_message_id=gmail_message_id,
            gmail_attachment_id=gmail_attachment_id,
            gmail_part_id=gmail_part_id,
            client_ip=client_ip,
            user_agent=user_agent,
        )
        return {
            "status": "PENDING_ANALYSIS",
            "enforcement_decision": "BLOCKED",
            "is_blocked": True,
            "filename": filename,
            "reason": "Attachment analysis is pending or identity has not been verified by SecureMailAnalyzer. Pre-download protection requires completed verification.",
            "investigation_id": None,
            "risk_score": None,
            "severity": None,
            "can_release": False,
        }

    # Evaluate decision using verified investigation results
    decision, reason, is_blocked = evaluate_enforcement_decision(
        risk_score=investigation["risk_score"],
        severity=investigation["severity"],
        sha256=investigation["sha256"],
        investigation_id=investigation["id"],
    )

    # Log enforcement event (tracks repeat clicks for blocked attachments)
    log_enforcement_event(
        filename=filename,
        action="BLOCKED" if is_blocked else decision,
        reason=reason,
        sha256=investigation["sha256"],
        gmail_message_id=gmail_message_id or investigation.get("gmail_message_id"),
        gmail_attachment_id=gmail_attachment_id or investigation.get("gmail_attachment_id"),
        gmail_part_id=gmail_part_id or investigation.get("gmail_part_id"),
        investigation_id=investigation["id"],
        risk_score=investigation["risk_score"],
        severity=investigation["severity"],
        client_ip=client_ip,
        user_agent=user_agent,
    )

    return {
        "status": "ANALYZED",
        "enforcement_decision": decision,
        "is_blocked": is_blocked,
        "filename": investigation["original_filename"],
        "reason": reason,
        "investigation_id": investigation["id"],
        "risk_score": investigation["risk_score"],
        "severity": investigation["severity"],
        "sha256": investigation["sha256"],
        "verdict": investigation["verdict"],
        "findings_count": len(investigation.get("findings", [])),
        "can_release": is_blocked,
        "is_released": decision == "RELEASED",
    }


def execute_authorized_release(
    investigation_id: str,
    authorized_by: str,
    reason: str,
    expiry_minutes: int = 15,
) -> Dict[str, Any]:
    """Execute an explicit, auditable security release for a blocked attachment."""
    if not authorized_by or len(authorized_by.strip()) < 2:
        raise ValueError("Authorized analyst identity is required (minimum 2 characters).")

    if not reason or len(reason.strip()) < 8:
        raise ValueError("A documented security justification (minimum 8 characters) is required.")

    inv = get_investigation(investigation_id)
    if not inv:
        raise ValueError(f"Investigation {investigation_id} not found.")

    release_record = create_release_authorization(
        investigation_id=investigation_id,
        authorized_by=authorized_by.strip(),
        reason=reason.strip(),
        expiry_minutes=expiry_minutes,
    )

    return {
        "success": True,
        "message": f"Attachment '{inv['original_filename']}' successfully authorized for single-use release.",
        "release": release_record,
        "auth_token": release_record["auth_token"],
        "expires_at": release_record["expires_at"],
        "enforcement_decision": "RELEASED",
        "is_blocked": False,
    }
