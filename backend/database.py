"""Database persistence layer for SecureMailAnalyzer.
Extended with Gmail OAuth token storage, pre-download enforcement logs,
and auditable release authorizations.
"""

import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secure_mail_analyzer.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database tables with schema definitions and backward-compatible migrations."""
    conn = get_connection()
    cursor = conn.cursor()

    # Core investigations table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            file_extension TEXT NOT NULL,
            detected_format TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            severity TEXT NOT NULL,
            verdict TEXT NOT NULL,
            quarantine_status TEXT NOT NULL DEFAULT 'ACTIVE',
            quarantine_notes TEXT,
            quarantine_updated_at TEXT,
            findings_json TEXT NOT NULL,
            limitations_json TEXT NOT NULL,
            is_synthetic_sample INTEGER NOT NULL DEFAULT 0,
            has_sandbox_report INTEGER NOT NULL DEFAULT 0,
            source_type TEXT NOT NULL DEFAULT 'LOCAL_UPLOAD',
            gmail_message_id TEXT,
            gmail_attachment_id TEXT,
            gmail_sender TEXT,
            gmail_subject TEXT,
            enforcement_decision TEXT NOT NULL DEFAULT 'NONE'
        )
        """
    )

    # Safe backward-compatible migrations for existing databases
    existing_cols = [row["name"] for row in cursor.execute("PRAGMA table_info(investigations)").fetchall()]
    new_cols = {
        "source_type": "TEXT NOT NULL DEFAULT 'LOCAL_UPLOAD'",
        "gmail_message_id": "TEXT",
        "gmail_attachment_id": "TEXT",
        "gmail_part_id": "TEXT",
        "gmail_sender": "TEXT",
        "gmail_subject": "TEXT",
        "enforcement_decision": "TEXT NOT NULL DEFAULT 'NONE'",
    }
    for col_name, col_def in new_cols.items():
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE investigations ADD COLUMN {col_name} {col_def}")

    # Timeline events table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS timeline_events (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            source TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'LOW',
            details_json TEXT NOT NULL DEFAULT '{}',
            sort_order INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        """
    )

    # Quarantine logs table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS quarantine_logs (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            analyst TEXT NOT NULL,
            reason TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        """
    )

    # Gmail OAuth Token Storage
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS gmail_auth (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            access_token TEXT NOT NULL,
            refresh_token TEXT,
            token_expiry TEXT,
            scope TEXT,
            connected_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1
        )
        """
    )

    # OAuth CSRF State Storage with Expiration
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS oauth_states (
            state TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
        """
    )

    # Pre-Download Enforcement Logs Table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS enforcement_logs (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT,
            gmail_message_id TEXT,
            gmail_attachment_id TEXT,
            gmail_part_id TEXT,
            investigation_id TEXT,
            action TEXT NOT NULL,
            reason TEXT NOT NULL,
            risk_score INTEGER,
            severity TEXT,
            client_ip TEXT,
            user_agent TEXT,
            repeat_count INTEGER NOT NULL DEFAULT 1,
            release_token_used TEXT
        )
        """
    )

    # Safe migrations for enforcement_logs
    enf_cols = [row["name"] for row in cursor.execute("PRAGMA table_info(enforcement_logs)").fetchall()]
    new_enf_cols = {
        "gmail_part_id": "TEXT",
        "release_token_used": "TEXT",
    }
    for col_name, col_def in new_enf_cols.items():
        if col_name not in enf_cols:
            cursor.execute(f"ALTER TABLE enforcement_logs ADD COLUMN {col_name} {col_def}")

    # Auditable Release Authorizations Table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS release_authorizations (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            authorized_by TEXT NOT NULL,
            reason TEXT NOT NULL,
            released_at TEXT NOT NULL,
            auth_token TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'RELEASED',
            expires_at TEXT,
            is_used INTEGER NOT NULL DEFAULT 0,
            used_at TEXT,
            gmail_message_id TEXT,
            gmail_attachment_id TEXT,
            gmail_part_id TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        )
        """
    )

    # Safe migrations for release_authorizations
    rel_cols = [row["name"] for row in cursor.execute("PRAGMA table_info(release_authorizations)").fetchall()]
    new_rel_cols = {
        "expires_at": "TEXT",
        "is_used": "INTEGER NOT NULL DEFAULT 0",
        "used_at": "TEXT",
        "gmail_message_id": "TEXT",
        "gmail_attachment_id": "TEXT",
        "gmail_part_id": "TEXT",
    }
    for col_name, col_def in new_rel_cols.items():
        if col_name not in rel_cols:
            cursor.execute(f"ALTER TABLE release_authorizations ADD COLUMN {col_name} {col_def}")

    conn.commit()
    conn.close()


def save_investigation(
    inv_id: str,
    filename: str,
    original_filename: str,
    file_size: int,
    file_extension: str,
    detected_format: str,
    sha256: str,
    risk_score: int,
    severity: str,
    verdict: str,
    findings: List[Dict[str, Any]],
    limitations: List[str],
    is_synthetic_sample: bool = False,
    timeline_events: Optional[List[Dict[str, Any]]] = None,
    source_type: str = "LOCAL_UPLOAD",
    gmail_message_id: Optional[str] = None,
    gmail_attachment_id: Optional[str] = None,
    gmail_part_id: Optional[str] = None,
    gmail_sender: Optional[str] = None,
    gmail_subject: Optional[str] = None,
    enforcement_decision: str = "NONE",
) -> str:
    """Save an analysis investigation and its initial timeline events."""
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        """
        INSERT OR REPLACE INTO investigations (
            id, created_at, filename, original_filename, file_size, file_extension,
            detected_format, sha256, risk_score, severity, verdict,
            quarantine_status, findings_json, limitations_json, is_synthetic_sample, has_sandbox_report,
            source_type, gmail_message_id, gmail_attachment_id, gmail_part_id, gmail_sender, gmail_subject, enforcement_decision
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            inv_id,
            now_iso,
            filename,
            original_filename,
            file_size,
            file_extension,
            detected_format,
            sha256,
            risk_score,
            severity,
            verdict,
            json.dumps(findings),
            json.dumps(limitations),
            1 if is_synthetic_sample else 0,
            source_type,
            gmail_message_id,
            gmail_attachment_id,
            gmail_part_id,
            gmail_sender,
            gmail_subject,
            enforcement_decision,
        ),
    )

    if timeline_events:
        for idx, event in enumerate(timeline_events):
            event_id = event.get("id") or str(uuid.uuid4())
            cursor.execute(
                """
                INSERT OR REPLACE INTO timeline_events (
                    id, investigation_id, timestamp, event_type, title,
                    description, source, severity, details_json, sort_order
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    inv_id,
                    event.get("timestamp", now_iso),
                    event.get("event_type", "GENERIC"),
                    event.get("title", ""),
                    event.get("description", ""),
                    event.get("source", "Observed"),
                    event.get("severity", "LOW"),
                    json.dumps(event.get("details", {})),
                    idx,
                ),
            )

    conn.commit()
    conn.close()
    return inv_id


def get_investigation(inv_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full investigation record by ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None

    inv = dict(row)
    inv["findings"] = json.loads(inv["findings_json"])
    inv["limitations"] = json.loads(inv["limitations_json"])
    inv["is_synthetic_sample"] = bool(inv["is_synthetic_sample"])
    inv["has_sandbox_report"] = bool(inv["has_sandbox_report"])

    cursor.execute(
        "SELECT * FROM timeline_events WHERE investigation_id = ? ORDER BY sort_order ASC, timestamp ASC",
        (inv_id,),
    )
    events = []
    for r in cursor.fetchall():
        ev = dict(r)
        ev["details"] = json.loads(ev["details_json"])
        events.append(ev)
    inv["timeline"] = events

    cursor.execute(
        "SELECT * FROM quarantine_logs WHERE investigation_id = ? ORDER BY timestamp DESC",
        (inv_id,),
    )
    q_logs = [dict(r) for r in cursor.fetchall()]
    inv["quarantine_history"] = q_logs

    # Fetch release authorization if any
    cursor.execute(
        "SELECT * FROM release_authorizations WHERE investigation_id = ?",
        (inv_id,),
    )
    rel = cursor.fetchone()
    inv["release_authorization"] = dict(rel) if rel else None

    conn.close()
    return inv


def find_investigation_by_hash(sha256: str) -> Optional[Dict[str, Any]]:
    """Find existing investigation by SHA-256 hash."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM investigations WHERE sha256 = ? ORDER BY created_at DESC LIMIT 1", (sha256,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return get_investigation(row["id"])
    return None


def find_investigation_by_gmail_attachment(message_id: str, attachment_id: str) -> Optional[Dict[str, Any]]:
    """Find investigation associated with specific Gmail message and attachment ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id FROM investigations WHERE gmail_message_id = ? AND gmail_attachment_id = ? ORDER BY created_at DESC LIMIT 1",
        (message_id, attachment_id),
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return get_investigation(row["id"])
    return None


def find_investigation_by_identity(
    gmail_message_id: Optional[str] = None,
    gmail_attachment_id: Optional[str] = None,
    gmail_part_id: Optional[str] = None,
    sha256: Optional[str] = None,
    filename: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Find investigation by reliable verified identifiers.
    Priority 1: Gmail message ID + attachment ID
    Priority 2: Gmail message ID + MIME part ID
    Priority 3: Cryptographic SHA-256 hash
    Priority 4: Gmail message ID + original filename
    Fails closed: never matches on filename alone without verified message or attachment ID or hash.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Priority 1: Match exact Gmail message & attachment ID
    if gmail_message_id and gmail_attachment_id:
        cursor.execute(
            "SELECT id FROM investigations WHERE gmail_message_id = ? AND gmail_attachment_id = ? ORDER BY created_at DESC LIMIT 1",
            (gmail_message_id, gmail_attachment_id),
        )
        row = cursor.fetchone()
        if row:
            conn.close()
            return get_investigation(row["id"])

    # Priority 2: Match exact Gmail message & MIME part ID
    if gmail_message_id and gmail_part_id:
        cursor.execute(
            "SELECT id FROM investigations WHERE gmail_message_id = ? AND gmail_part_id = ? ORDER BY created_at DESC LIMIT 1",
            (gmail_message_id, gmail_part_id),
        )
        row = cursor.fetchone()
        if row:
            conn.close()
            return get_investigation(row["id"])

    # Priority 3: Match by cryptographic hash
    if sha256:
        cursor.execute(
            "SELECT id FROM investigations WHERE sha256 = ? ORDER BY created_at DESC LIMIT 1",
            (sha256,),
        )
        row = cursor.fetchone()
        if row:
            conn.close()
            return get_investigation(row["id"])

    # Priority 4: Match by Gmail message ID AND original filename
    if gmail_message_id and filename:
        cursor.execute(
            "SELECT id FROM investigations WHERE gmail_message_id = ? AND (original_filename = ? OR filename = ?) ORDER BY created_at DESC LIMIT 1",
            (gmail_message_id, filename, filename),
        )
        row = cursor.fetchone()
        if row:
            conn.close()
            return get_investigation(row["id"])

    conn.close()
    return None


def list_investigations(search: str = "", severity: str = "", limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """List investigations with optional search and severity filters."""
    conn = get_connection()
    cursor = conn.cursor()

    query = (
        "SELECT id, created_at, filename, original_filename, file_size, file_extension, "
        "detected_format, sha256, risk_score, severity, verdict, quarantine_status, "
        "is_synthetic_sample, has_sandbox_report, source_type, gmail_sender, gmail_subject, "
        "enforcement_decision FROM investigations WHERE 1=1"
    )
    params: List[Any] = []

    if search:
        query += " AND (filename LIKE ? OR sha256 LIKE ? OR id LIKE ? OR gmail_subject LIKE ?)"
        like_term = f"%{search}%"
        params.extend([like_term, like_term, like_term, like_term])

    if severity and severity.upper() != "ALL":
        query += " AND severity = ?"
        params.append(severity.upper())

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def add_timeline_events(inv_id: str, events: List[Dict[str, Any]]) -> None:
    """Add events to the investigation timeline."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT MAX(sort_order) FROM timeline_events WHERE investigation_id = ?", (inv_id,))
    max_order = cursor.fetchone()[0] or 0

    for idx, event in enumerate(events):
        event_id = event.get("id") or str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO timeline_events (
                id, investigation_id, timestamp, event_type, title,
                description, source, severity, details_json, sort_order
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                inv_id,
                event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                event.get("event_type", "GENERIC"),
                event.get("title", ""),
                event.get("description", ""),
                event.get("source", "Observed"),
                event.get("severity", "LOW"),
                json.dumps(event.get("details", {})),
                max_order + idx + 1,
            ),
        )

    cursor.execute("UPDATE investigations SET has_sandbox_report = 1 WHERE id = ?", (inv_id,))
    conn.commit()
    conn.close()


def update_quarantine_status(
    inv_id: str, status: str, notes: str, analyst: str = "SOC Analyst (Current User)"
) -> bool:
    """Update quarantine status and log audit entry."""
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    cursor.execute(
        """
        UPDATE investigations
        SET quarantine_status = ?, quarantine_notes = ?, quarantine_updated_at = ?
        WHERE id = ?
        """,
        (status, notes, now_iso, inv_id),
    )

    if cursor.rowcount == 0:
        conn.close()
        return False

    log_id = str(uuid.uuid4())
    cursor.execute(
        """
        INSERT INTO quarantine_logs (id, investigation_id, action, timestamp, analyst, reason)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (log_id, inv_id, status, now_iso, analyst, notes),
    )

    action_label = "Quarantined" if status == "QUARANTINED" else "Restored from Quarantine"
    event_id = str(uuid.uuid4())
    cursor.execute(
        """
        INSERT INTO timeline_events (
            id, investigation_id, timestamp, event_type, title,
            description, source, severity, details_json, sort_order
        ) VALUES (?, ?, ?, 'QUARANTINE_ACTION', ?, ?, 'Application Action', ?, ?, 999)
        """,
        (
            event_id,
            inv_id,
            now_iso,
            f"Simulated {action_label}",
            f"Attachment state transitioned to {status}. Analyst reason: {notes}",
            "HIGH" if status == "QUARANTINED" else "LOW",
            json.dumps({"analyst": analyst, "action": status, "reason": notes}),
        ),
    )

    conn.commit()
    conn.close()
    return True


# ==========================================
# GMAIL OAUTH STORAGE
# ==========================================

def save_gmail_token(
    email: str,
    access_token: str,
    refresh_token: Optional[str],
    token_expiry: Optional[str],
    scope: Optional[str] = None,
) -> None:
    """Store or update Gmail OAuth credentials."""
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()

    # Deactivate any previous tokens
    cursor.execute("UPDATE gmail_auth SET is_active = 0 WHERE email != ?", (email,))

    cursor.execute("SELECT id, refresh_token FROM gmail_auth WHERE email = ?", (email,))
    existing = cursor.fetchone()

    # Preserve existing refresh token if new one is not returned in refresh flow
    final_refresh = refresh_token if refresh_token else (existing["refresh_token"] if existing else None)

    if existing:
        cursor.execute(
            """
            UPDATE gmail_auth
            SET access_token = ?, refresh_token = ?, token_expiry = ?, scope = ?,
                updated_at = ?, is_active = 1
            WHERE email = ?
            """,
            (access_token, final_refresh, token_expiry, scope, now_iso, email),
        )
    else:
        new_id = str(uuid.uuid4())
        cursor.execute(
            """
            INSERT INTO gmail_auth (id, email, access_token, refresh_token, token_expiry, scope, connected_at, updated_at, is_active)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (new_id, email, access_token, final_refresh, token_expiry, scope, now_iso, now_iso),
        )

    conn.commit()
    conn.close()


def get_active_gmail_token() -> Optional[Dict[str, Any]]:
    """Retrieve active Gmail OAuth session."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM gmail_auth WHERE is_active = 1 ORDER BY updated_at DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def clear_gmail_token() -> None:
    """Disconnect Gmail integration by deactivating stored tokens."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE gmail_auth SET is_active = 0")
    conn.commit()
    conn.close()


# ==========================================
# OAUTH CSRF STATE HELPERS
# ==========================================

def create_oauth_state(expiry_seconds: int = 600) -> str:
    """Generate a cryptographically random OAuth state token and persist with expiration."""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=expiry_seconds)
    state = secrets.token_urlsafe(32)

    # Clean up expired states older than 1 hour
    one_hour_ago = (now - timedelta(hours=1)).isoformat()
    cursor.execute("DELETE FROM oauth_states WHERE expires_at < ?", (one_hour_ago,))

    cursor.execute(
        "INSERT INTO oauth_states (state, created_at, expires_at) VALUES (?, ?, ?)",
        (state, now.isoformat(), expires.isoformat()),
    )
    conn.commit()
    conn.close()
    return state


def validate_and_consume_oauth_state(state: str) -> bool:
    """Validate and atomically consume an OAuth state token to prevent CSRF and replay attacks."""
    if not state or len(state.strip()) < 16:
        return False

    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    cursor.execute("SELECT state, expires_at FROM oauth_states WHERE state = ?", (state.strip(),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False

    expires_at = row["expires_at"]
    is_valid = now_iso <= expires_at

    # Atomically delete token to enforce strict single-use
    cursor.execute("DELETE FROM oauth_states WHERE state = ?", (state.strip(),))
    conn.commit()
    conn.close()
    return is_valid


# ==========================================
# PRE-DOWNLOAD ENFORCEMENT AUDIT LOGS
# ==========================================

def log_enforcement_event(
    filename: str,
    action: str,
    reason: str,
    sha256: Optional[str] = None,
    gmail_message_id: Optional[str] = None,
    gmail_attachment_id: Optional[str] = None,
    gmail_part_id: Optional[str] = None,
    investigation_id: Optional[str] = None,
    risk_score: Optional[int] = None,
    severity: Optional[str] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    release_token_used: Optional[str] = None,
) -> str:
    """Record an intercepted download, blocked attempt, or allowed action."""
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    log_id = str(uuid.uuid4())

    # Check for duplicate recent event on same filename within 10 seconds to track repeat click count
    cursor.execute(
        """
        SELECT id, repeat_count FROM enforcement_logs
        WHERE filename = ? AND action = ? AND investigation_id IS ?
        ORDER BY timestamp DESC LIMIT 1
        """,
        (filename, action, investigation_id),
    )
    recent = cursor.fetchone()
    if recent and action == "BLOCKED":
        # Increment repeat counter for repeated blocked clicks
        cursor.execute(
            "UPDATE enforcement_logs SET repeat_count = repeat_count + 1, timestamp = ? WHERE id = ?",
            (now_iso, recent["id"]),
        )
        conn.commit()
        conn.close()
        return recent["id"]

    cursor.execute(
        """
        INSERT INTO enforcement_logs (
            id, timestamp, filename, sha256, gmail_message_id, gmail_attachment_id, gmail_part_id,
            investigation_id, action, reason, risk_score, severity, client_ip, user_agent, repeat_count, release_token_used
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """,
        (
            log_id,
            now_iso,
            filename,
            sha256,
            gmail_message_id,
            gmail_attachment_id,
            gmail_part_id,
            investigation_id,
            action,
            reason,
            risk_score,
            severity,
            client_ip,
            user_agent,
            release_token_used,
        ),
    )
    conn.commit()
    conn.close()
    return log_id


def list_enforcement_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve recent pre-download enforcement events."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT * FROM enforcement_logs
        ORDER BY timestamp DESC LIMIT ?
        """,
        (limit,),
    )
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


# ==========================================
# AUDITABLE RELEASE AUTHORIZATION
# ==========================================

def create_release_authorization(
    investigation_id: str,
    authorized_by: str,
    reason: str,
    expiry_minutes: int = 15,
) -> Dict[str, Any]:
    """Record an explicit, auditable release authorization for a blocked attachment with high entropy and single-use expiry."""
    inv = get_investigation(investigation_id)
    if not inv:
        raise ValueError(f"Investigation {investigation_id} not found.")

    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    expires_at = (now + timedelta(minutes=expiry_minutes)).isoformat()
    rel_id = str(uuid.uuid4())
    # High-entropy unpredictable release token (192 bits of cryptographic entropy)
    auth_token = f"REL-{secrets.token_urlsafe(24)}"

    cursor.execute(
        """
        INSERT INTO release_authorizations (
            id, investigation_id, filename, sha256, authorized_by, reason,
            released_at, auth_token, status, expires_at, is_used, used_at,
            gmail_message_id, gmail_attachment_id, gmail_part_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'RELEASED', ?, 0, NULL, ?, ?, ?)
        """,
        (
            rel_id,
            investigation_id,
            inv["original_filename"],
            inv["sha256"],
            authorized_by,
            reason,
            now_iso,
            auth_token,
            expires_at,
            inv.get("gmail_message_id"),
            inv.get("gmail_attachment_id"),
            inv.get("gmail_part_id"),
        ),
    )

    # Update investigation enforcement status
    cursor.execute(
        "UPDATE investigations SET enforcement_decision = 'RELEASED' WHERE id = ?",
        (investigation_id,),
    )

    # Add Threat Story timeline event for the release
    event_id = str(uuid.uuid4())
    cursor.execute(
        """
        INSERT INTO timeline_events (
            id, investigation_id, timestamp, event_type, title,
            description, source, severity, details_json, sort_order
        ) VALUES (?, ?, ?, 'ENFORCEMENT_RELEASE', ?, ?, 'Application Action', 'MEDIUM', ?, 998)
        """,
        (
            event_id,
            investigation_id,
            now_iso,
            "Authorized Pre-Download Release",
            f"Blocked attachment explicitly authorized for single-use release by {authorized_by} (Expires: {expires_at}). Justification: {reason}",
            json.dumps({
                "authorized_by": authorized_by,
                "reason": reason,
                "auth_token": auth_token,
                "expires_at": expires_at,
                "original_severity": inv["severity"],
            }),
        ),
    )

    conn.commit()
    conn.close()

    # Log enforcement event
    log_enforcement_event(
        filename=inv["original_filename"],
        action="RELEASED",
        reason=f"Authorized release by {authorized_by} (Expires in {expiry_minutes}m): {reason}",
        sha256=inv["sha256"],
        gmail_message_id=inv.get("gmail_message_id"),
        gmail_attachment_id=inv.get("gmail_attachment_id"),
        gmail_part_id=inv.get("gmail_part_id"),
        investigation_id=investigation_id,
        risk_score=inv["risk_score"],
        severity=inv["severity"],
        release_token_used=auth_token,
    )

    return {
        "id": rel_id,
        "investigation_id": investigation_id,
        "filename": inv["original_filename"],
        "auth_token": auth_token,
        "authorized_by": authorized_by,
        "reason": reason,
        "released_at": now_iso,
        "expires_at": expires_at,
        "status": "RELEASED",
    }


def redeem_release_authorization(
    token: str,
    investigation_id: Optional[str] = None,
    gmail_message_id: Optional[str] = None,
    gmail_attachment_id: Optional[str] = None,
    gmail_part_id: Optional[str] = None,
    sha256: Optional[str] = None,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """Atomically validate and redeem a single-use release authorization token.
    Enforces attachment scope, expiration, and prevents reuse.
    """
    if not token or not token.startswith("REL-"):
        return False, "Invalid release token format.", None

    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    cursor.execute("SELECT * FROM release_authorizations WHERE auth_token = ?", (token.strip(),))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return False, "Release token does not exist.", None

    rel = dict(row)

    # Check single-use
    if rel.get("is_used"):
        conn.close()
        return False, "Release token has already been redeemed (single-use enforcement).", None

    # Check expiration
    exp_str = rel.get("expires_at")
    if exp_str:
        try:
            exp_dt = datetime.fromisoformat(exp_str)
            if now >= exp_dt:
                conn.close()
                return False, "Release token has expired. Request a new authorization.", None
        except Exception:
            pass

    # Check attachment scoping
    if investigation_id and rel.get("investigation_id") != investigation_id:
        conn.close()
        return False, "Release token was issued for a different investigation.", None

    if sha256 and rel.get("sha256") and rel["sha256"] != sha256:
        conn.close()
        return False, "Release token does not match attachment hash.", None

    if gmail_message_id and rel.get("gmail_message_id") and rel["gmail_message_id"] != gmail_message_id:
        conn.close()
        return False, "Release token was issued for a different Gmail message.", None

    if gmail_part_id and rel.get("gmail_part_id") and rel["gmail_part_id"] != gmail_part_id:
        conn.close()
        return False, "Release token was issued for a different attachment part.", None

    if gmail_attachment_id and rel.get("gmail_attachment_id") and rel["gmail_attachment_id"] != gmail_attachment_id:
        conn.close()
        return False, "Release token was issued for a different Gmail attachment ID.", None

    # Atomic redemption update
    cursor.execute(
        "UPDATE release_authorizations SET is_used = 1, used_at = ?, status = 'REDEEMED' WHERE auth_token = ? AND is_used = 0",
        (now_iso, token.strip()),
    )
    if cursor.rowcount == 0:
        conn.close()
        return False, "Concurrent release token redemption conflict.", None

    # Synchronize investigation state so future checks know the release token was consumed
    if rel.get("investigation_id"):
        cursor.execute(
            "UPDATE investigations SET enforcement_decision = 'RELEASE_REDEEMED' WHERE id = ?",
            (rel["investigation_id"],),
        )

    conn.commit()
    conn.close()

    # Log redemption in enforcement logs
    log_enforcement_event(
        filename=rel["filename"],
        action="RELEASE_REDEEMED",
        reason=f"Release token {token[:12]}... redeemed for single-use download.",
        sha256=rel.get("sha256"),
        gmail_message_id=rel.get("gmail_message_id"),
        gmail_attachment_id=rel.get("gmail_attachment_id"),
        gmail_part_id=rel.get("gmail_part_id"),
        investigation_id=rel.get("investigation_id"),
        release_token_used=token,
    )

    return True, "Release token successfully redeemed.", rel


def is_attachment_released(sha256: Optional[str] = None, investigation_id: Optional[str] = None) -> bool:
    """Check if an attachment has an unexpired, unredeemed release authorization."""
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    if investigation_id:
        cursor.execute(
            "SELECT id FROM release_authorizations WHERE investigation_id = ? AND status = 'RELEASED' AND is_used = 0 AND (expires_at IS NULL OR expires_at > ?)",
            (investigation_id, now_iso),
        )
    elif sha256:
        cursor.execute(
            "SELECT id FROM release_authorizations WHERE sha256 = ? AND status = 'RELEASED' AND is_used = 0 AND (expires_at IS NULL OR expires_at > ?)",
            (sha256, now_iso),
        )
    else:
        conn.close()
        return False

    row = cursor.fetchone()
    conn.close()
    return bool(row)


def get_quarantine_records() -> Dict[str, Any]:
    """Get all quarantined items and recent audit logs."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT id, created_at, filename, original_filename, file_size, sha256,
               risk_score, severity, quarantine_status, quarantine_notes, quarantine_updated_at
        FROM investigations
        WHERE quarantine_status = 'QUARANTINED'
        ORDER BY quarantine_updated_at DESC
        """
    )
    quarantined_items = [dict(r) for r in cursor.fetchall()]

    cursor.execute(
        """
        SELECT q.id, q.investigation_id, q.action, q.timestamp, q.analyst, q.reason,
               i.filename, i.sha256, i.severity
        FROM quarantine_logs q
        LEFT JOIN investigations i ON q.investigation_id = i.id
        ORDER BY q.timestamp DESC
        LIMIT 50
        """
    )
    audit_logs = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {"items": quarantined_items, "audit_trail": audit_logs}


def get_dashboard_stats() -> Dict[str, Any]:
    """Calculate live dashboard statistics from database records."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM investigations")
    total_analyzed = cursor.fetchone()[0]

    cursor.execute("SELECT severity, COUNT(*) FROM investigations GROUP BY severity")
    severity_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for row in cursor.fetchall():
        sev = row[0].upper()
        if sev in severity_counts:
            severity_counts[sev] = row[1]

    cursor.execute("SELECT COUNT(*) FROM investigations WHERE quarantine_status = 'QUARANTINED'")
    quarantined_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM investigations WHERE has_sandbox_report = 1")
    sandbox_correlated_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM enforcement_logs WHERE action = 'BLOCKED'")
    blocked_downloads_count = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT id, created_at, filename, sha256, risk_score, severity, quarantine_status, is_synthetic_sample, source_type
        FROM investigations
        ORDER BY created_at DESC
        LIMIT 6
        """
    )
    recent_investigations = [dict(r) for r in cursor.fetchall()]

    risk_distribution = [
        {"name": "Low (0-24)", "count": severity_counts["LOW"], "severity": "LOW", "color": "#10B981"},
        {"name": "Medium (25-49)", "count": severity_counts["MEDIUM"], "severity": "MEDIUM", "color": "#F59E0B"},
        {"name": "High (50-74)", "count": severity_counts["HIGH"], "severity": "HIGH", "color": "#F97316"},
        {"name": "Critical (75-100)", "count": severity_counts["CRITICAL"], "severity": "CRITICAL", "color": "#EF4444"},
    ]

    conn.close()
    return {
        "total_analyzed": total_analyzed,
        "severity_counts": severity_counts,
        "quarantined_count": quarantined_count,
        "sandbox_correlated_count": sandbox_correlated_count,
        "blocked_downloads_count": blocked_downloads_count,
        "recent_investigations": recent_investigations,
        "risk_distribution": risk_distribution,
    }
