"""Flask Application Server for SecureMailAnalyzer.
Exposes REST APIs for file inspection, risk scoring, Attachment Threat Story,
sandbox JSON ingestion, quarantine simulation, and security reporting.
"""

import json
import os
import re
import urllib.parse
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Flask, Response, jsonify, request, send_from_directory
from flask_cors import CORS

from analyzer import analyze_file, sanitize_filename
from database import (
    add_timeline_events,
    get_dashboard_stats,
    get_investigation,
    get_quarantine_records,
    init_db,
    list_enforcement_logs,
    list_investigations,
    save_investigation,
    update_quarantine_status,
    validate_and_consume_oauth_state,
)
from enforcement_engine import (
    check_attachment_enforcement_status,
    evaluate_enforcement_decision,
    execute_authorized_release,
)
from gmail_service import (
    clear_gmail_token,
    exchange_code_for_tokens,
    generate_auth_url,
    get_gmail_connection_status,
    get_message_attachments_metadata,
    get_oauth_config,
    list_messages_with_attachments,
    retrieve_attachment_bytes,
    save_oauth_config,
)
from report_generator import generate_csv_report, generate_json_report
from risk_engine import evaluate_risk
from sandbox_parser import validate_and_parse_sandbox_report
from timeline import generate_initial_threat_story

app = Flask(__name__, static_folder="../frontend/dist", static_url_path="")

# Strict CORS origin restrictions (prevent unauthorized cross-origin requests from foreign web pages)
ALLOWED_ORIGINS = [
    "http://127.0.0.1:5000",
    "http://localhost:5000",
    "http://127.0.0.1:3000",
    "http://localhost:3000",
]
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": ALLOWED_ORIGINS + [re.compile(r"^chrome-extension://[a-z0-9]+$")],
            "methods": ["GET", "POST", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "X-SMA-Client"],
        }
    },
)

# Sample files mapping
SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_data")
SAMPLES_CATALOG = {
    "benign": {
        "id": "benign",
        "name": "sample_benign_document.txt",
        "display_name": "Harmless Financial Memo (.txt)",
        "description": "Completely benign plain text memo with zero active macros, scripts, or embedded elements. Expected Score: 0 (LOW).",
        "file_path": os.path.join(SAMPLE_DIR, "sample_benign_document.txt"),
        "expected_severity": "LOW",
    },
    "double_ext": {
        "id": "double_ext",
        "name": "suspicious_invoice_double_ext.pdf.bat",
        "display_name": "Invoice with Double Extension (.pdf.bat)",
        "description": "Synthetic script disguised with deceptive double extension and hidden PowerShell execution switch. Expected Score: 70-85 (HIGH/CRITICAL).",
        "file_path": os.path.join(SAMPLE_DIR, "suspicious_invoice_double_ext.pdf.bat"),
        "expected_severity": "CRITICAL",
    },
    "macro": {
        "id": "macro",
        "name": "suspicious_macro_sample.docm",
        "display_name": "Macro-Enabled Office Container (.docm)",
        "description": "Safe synthetic Word OpenXML container housing a vbaProject.bin macro storage structure. Expected Score: 50-65 (HIGH).",
        "file_path": os.path.join(SAMPLE_DIR, "suspicious_macro_sample.docm"),
        "expected_severity": "HIGH",
    },
    "js_pdf": {
        "id": "js_pdf",
        "name": "suspicious_js_sample.pdf",
        "display_name": "PDF with Embedded JavaScript & AutoAction (.pdf)",
        "description": "Safe synthetic PDF structure containing /OpenAction and /JavaScript interactive tags. Expected Score: 50-60 (HIGH).",
        "file_path": os.path.join(SAMPLE_DIR, "suspicious_js_sample.pdf"),
        "expected_severity": "HIGH",
    },
}


def verify_origin_protection() -> Tuple[bool, str]:
    """Verify that Origin header, if supplied by browser, matches allowed local/extension origins."""
    origin = request.headers.get("Origin")
    if origin:
        if origin not in ALLOWED_ORIGINS and not origin.startswith("chrome-extension://"):
            return False, "Cross-origin request rejected."
    return True, ""


@app.before_request
def setup_if_needed():
    # Ensure database tables exist
    init_db()

    # Validate Host header to protect against DNS rebinding attacks targeting localhost
    host_header = request.host.split(":")[0].lower()
    if host_header not in {"127.0.0.1", "localhost", "testserver"}:
        return jsonify({"error": "Invalid Host header. Access rejected."}), 400


@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "HEALTHY",
        "service": "SecureMailAnalyzer Engine",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0",
        "database": "SQLite Initialized",
    })


@app.route("/api/stats", methods=["GET"])
def dashboard_stats():
    """Retrieve live statistics aggregated from investigation database."""
    stats = get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/analyze", methods=["POST"])
def analyze_attachment():
    """Handle attachment upload and execute static analysis pipeline."""
    if "file" not in request.files:
        return jsonify({"error": "No file part provided in multipart request."}), 400

    uploaded_file = request.files["file"]
    if not uploaded_file.filename:
        return jsonify({"error": "No filename specified in upload."}), 400

    raw_bytes = uploaded_file.read()
    orig_name = uploaded_file.filename
    is_sample = request.form.get("is_sample", "false").lower() == "true"

    analysis = analyze_file(orig_name, raw_bytes, orig_name)
    if "error" in analysis:
        return jsonify({"error": analysis["error"]}), 400

    risk_result = evaluate_risk(analysis["findings"])
    inv_id = f"SMA-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    timeline_events = generate_initial_threat_story(
        filename=analysis["filename"],
        original_filename=analysis["original_filename"],
        file_size=analysis["file_size"],
        file_extension=analysis["file_extension"],
        detected_format=analysis["detected_format"],
        sha256=analysis["sha256"],
        findings=risk_result["annotated_findings"],
        risk_score=risk_result["risk_score"],
        severity=risk_result["severity"],
        verdict=risk_result["verdict"],
        is_synthetic_sample=is_sample,
    )

    save_investigation(
        inv_id=inv_id,
        filename=analysis["filename"],
        original_filename=analysis["original_filename"],
        file_size=analysis["file_size"],
        file_extension=analysis["file_extension"],
        detected_format=analysis["detected_format"],
        sha256=analysis["sha256"],
        risk_score=risk_result["risk_score"],
        severity=risk_result["severity"],
        verdict=risk_result["verdict"],
        findings=risk_result["annotated_findings"],
        limitations=analysis["limitations"],
        is_synthetic_sample=is_sample,
        timeline_events=timeline_events,
    )

    full_record = get_investigation(inv_id)
    if full_record:
        full_record["risk_evaluation"] = risk_result
        return jsonify(full_record), 201

    return jsonify({"error": "Failed to persist investigation."}), 500


@app.route("/api/samples", methods=["GET"])
def get_samples_list():
    """Return catalog of safe pre-packaged synthetic fixtures."""
    samples = []
    for s_id, s in SAMPLES_CATALOG.items():
        exists = os.path.exists(s["file_path"])
        size_bytes = os.path.getsize(s["file_path"]) if exists else 0
        samples.append({
            "id": s_id,
            "name": s["name"],
            "display_name": s["display_name"],
            "description": s["description"],
            "size_bytes": size_bytes,
            "expected_severity": s["expected_severity"],
            "available": exists,
        })
    return jsonify({"samples": samples})


@app.route("/api/samples/load/<sample_id>", methods=["POST"])
def load_sample_fixture(sample_id: str):
    """One-click analysis trigger for demonstration samples."""
    sample_meta = SAMPLES_CATALOG.get(sample_id)
    if not sample_meta:
        return jsonify({"error": f"Unknown sample ID '{sample_id}'."}), 404

    path = sample_meta["file_path"]
    if not os.path.exists(path):
        return jsonify({"error": f"Sample fixture file not found on server at '{path}'."}), 404

    with open(path, "rb") as f:
        raw_bytes = f.read()

    analysis = analyze_file(sample_meta["name"], raw_bytes, sample_meta["name"])
    if "error" in analysis:
        return jsonify({"error": analysis["error"]}), 400

    risk_result = evaluate_risk(analysis["findings"])
    inv_id = f"SMA-DEMO-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    timeline_events = generate_initial_threat_story(
        filename=analysis["filename"],
        original_filename=analysis["original_filename"],
        file_size=analysis["file_size"],
        file_extension=analysis["file_extension"],
        detected_format=analysis["detected_format"],
        sha256=analysis["sha256"],
        findings=risk_result["annotated_findings"],
        risk_score=risk_result["risk_score"],
        severity=risk_result["severity"],
        verdict=risk_result["verdict"],
        is_synthetic_sample=True,
    )

    save_investigation(
        inv_id=inv_id,
        filename=analysis["filename"],
        original_filename=analysis["original_filename"],
        file_size=analysis["file_size"],
        file_extension=analysis["file_extension"],
        detected_format=analysis["detected_format"],
        sha256=analysis["sha256"],
        risk_score=risk_result["risk_score"],
        severity=risk_result["severity"],
        verdict=risk_result["verdict"],
        findings=risk_result["annotated_findings"],
        limitations=analysis["limitations"],
        is_synthetic_sample=True,
        timeline_events=timeline_events,
    )

    full_record = get_investigation(inv_id)
    if full_record:
        full_record["risk_evaluation"] = risk_result
        return jsonify(full_record), 201

    return jsonify({"error": "Failed to process sample fixture."}), 500


@app.route("/api/samples/synthetic-sandbox", methods=["GET"])
def get_synthetic_sandbox_json():
    """Retrieve the sample synthetic sandbox JSON content."""
    sandbox_path = os.path.join(SAMPLE_DIR, "synthetic_sandbox_report.json")
    if not os.path.exists(sandbox_path):
        return jsonify({"error": "Synthetic sandbox report file not found."}), 404
    with open(sandbox_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return jsonify(data)


@app.route("/api/investigations", methods=["GET"])
def list_all_investigations():
    """List investigations with optional search, severity filter, and pagination."""
    search = request.args.get("search", "").strip()
    severity = request.args.get("severity", "").strip()
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    results = list_investigations(search=search, severity=severity, limit=limit, offset=offset)
    return jsonify({"investigations": results, "count": len(results)})


@app.route("/api/investigations/<inv_id>", methods=["GET"])
def get_single_investigation(inv_id: str):
    """Retrieve full investigation details including timeline and findings."""
    inv = get_investigation(inv_id)
    if not inv:
        return jsonify({"error": f"Investigation '{inv_id}' not found."}), 404

    # Reconstruct risk evaluation summary
    risk_result = evaluate_risk(inv["findings"])
    inv["risk_evaluation"] = risk_result
    return jsonify(inv)


@app.route("/api/investigations/<inv_id>/sandbox", methods=["POST"])
def import_sandbox_report(inv_id: str):
    """Upload or paste a sandbox JSON report to correlate into Attachment Threat Story."""
    inv = get_investigation(inv_id)
    if not inv:
        return jsonify({"error": f"Investigation '{inv_id}' not found."}), 404

    json_payload = None
    if "file" in request.files:
        file = request.files["file"]
        try:
            content = file.read().decode("utf-8")
            json_payload = json.loads(content)
        except Exception as e:
            return jsonify({"error": f"Failed to parse uploaded JSON file: {str(e)}"}), 400
    elif request.is_json:
        json_payload = request.get_json()
    else:
        # Check raw body
        try:
            raw_text = request.get_data(as_text=True)
            if raw_text:
                json_payload = json.loads(raw_text)
        except Exception as e:
            return jsonify({"error": f"Invalid JSON payload: {str(e)}"}), 400

    if not json_payload:
        return jsonify({"error": "No JSON data provided. Please upload a file or supply JSON body."}), 400

    is_valid, err_msg, parsed_events, metadata = validate_and_parse_sandbox_report(json_payload)
    if not is_valid:
        return jsonify({"error": f"Sandbox Report Validation Error: {err_msg}"}), 400

    # Add header event for sandbox intake
    intake_event = {
        "id": str(uuid.uuid4()),
        "event_type": "SANDBOX_IMPORT_HEADER",
        "title": f"External Sandbox Report Imported ({metadata.get('analyzer_version', 'Dynamic VM')})",
        "description": f"Ingested {len(parsed_events)} behavioral events. Analysis duration: {metadata.get('execution_time_seconds', 0)}s. {metadata.get('disclaimer')}",
        "source": "Imported Sandbox Report",
        "severity": "MEDIUM",
        "timestamp": metadata.get("imported_at"),
        "details": metadata,
    }

    all_new_events = [intake_event] + parsed_events
    add_timeline_events(inv_id, all_new_events)

    updated_inv = get_investigation(inv_id)
    if updated_inv:
        updated_inv["risk_evaluation"] = evaluate_risk(updated_inv["findings"])
        return jsonify({
            "message": f"Successfully correlated {len(parsed_events)} sandbox events into Threat Story.",
            "investigation": updated_inv,
        })

    return jsonify({"error": "Failed to update investigation."}), 500


@app.route("/api/investigations/<inv_id>/quarantine", methods=["POST"])
def toggle_quarantine(inv_id: str):
    """Simulate quarantine or restoration of an attachment."""
    ok_origin, err_origin = verify_origin_protection()
    if not ok_origin:
        return jsonify({"error": err_origin}), 403

    inv = get_investigation(inv_id)
    if not inv:
        return jsonify({"error": f"Investigation '{inv_id}' not found."}), 404

    data = request.get_json() or {}
    new_status = data.get("status", "QUARANTINED").upper()
    if new_status not in {"QUARANTINED", "RESTORED", "ACTIVE"}:
        return jsonify({"error": "Status must be 'QUARANTINED', 'RESTORED', or 'ACTIVE'."}), 400

    notes = data.get("notes", "Analyst simulated containment action via SecureMailAnalyzer SOC console.")
    analyst = data.get("analyst", "SOC Analyst")

    success = update_quarantine_status(inv_id, new_status, notes, analyst)
    if not success:
        return jsonify({"error": "Failed to update quarantine state."}), 500

    updated_inv = get_investigation(inv_id)
    if updated_inv:
        updated_inv["risk_evaluation"] = evaluate_risk(updated_inv["findings"])
        return jsonify({
            "message": f"Attachment status updated to {new_status}.",
            "investigation": updated_inv,
        })

    return jsonify({"error": "Failed to retrieve updated record."}), 500


@app.route("/api/quarantine", methods=["GET"])
def list_quarantine():
    """Retrieve list of quarantined attachments and audit trail."""
    records = get_quarantine_records()
    return jsonify(records)


@app.route("/api/investigations/<inv_id>/export/json", methods=["GET"])
def export_investigation_json(inv_id: str):
    """Download full investigation report as structured JSON."""
    inv = get_investigation(inv_id)
    if not inv:
        return jsonify({"error": f"Investigation '{inv_id}' not found."}), 404

    json_str = generate_json_report(inv)
    return Response(
        json_str,
        mimetype="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=SecureMailAnalyzer_Report_{inv_id}.json",
            "Cache-Control": "no-cache",
        },
    )


@app.route("/api/investigations/<inv_id>/export/csv", methods=["GET"])
def export_investigation_csv(inv_id: str):
    """Download investigation summary as CSV."""
    inv = get_investigation(inv_id)
    if not inv:
        return jsonify({"error": f"Investigation '{inv_id}' not found."}), 404

    csv_str = generate_csv_report(inv)
    return Response(
        csv_str,
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f"attachment; filename=SecureMailAnalyzer_Summary_{inv_id}.csv",
            "Cache-Control": "no-cache",
        },
    )


# =====================================================================
# GMAIL INTEGRATION ENDPOINTS
# =====================================================================

@app.route("/api/gmail/status", methods=["GET"])
def gmail_status():
    """Retrieve current Gmail OAuth connection status and configuration."""
    status = get_gmail_connection_status()
    return jsonify(status)


@app.route("/api/gmail/auth-url", methods=["GET"])
def gmail_auth_url():
    """Generate official Google OAuth 2.0 authorization URL with cryptographically secure CSRF state."""
    custom_state = request.args.get("state")
    ok, result = generate_auth_url(state=custom_state)
    if not ok:
        return jsonify({"error": result}), 400
    return jsonify({"auth_url": result})


@app.route("/api/gmail/config", methods=["POST"])
def configure_gmail_oauth():
    """Save or update Google OAuth Client ID and Secret."""
    ok_origin, err_origin = verify_origin_protection()
    if not ok_origin:
        return jsonify({"error": err_origin}), 403

    data = request.get_json() or {}
    client_id = data.get("client_id", "").strip()
    client_secret = data.get("client_secret", "").strip()
    redirect_uri = data.get("redirect_uri", "").strip() or None

    if not client_id or not client_secret:
        return jsonify({"error": "Both Google Client ID and Client Secret are required."}), 400

    save_oauth_config(client_id, client_secret, redirect_uri)
    return jsonify({
        "message": "OAuth credentials configured successfully.",
        "status": get_gmail_connection_status(),
    })


@app.route("/api/gmail/callback", methods=["GET"])
def gmail_oauth_callback():
    """Handle OAuth 2.0 authorization code redirect from Google with strict CSRF state validation."""
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")

    if error:
        return f"""
        <html>
        <body style="background:#090d16;color:#f87171;font-family:sans-serif;padding:40px;text-align:center;">
            <h2>Google OAuth Authorization Failed</h2>
            <p>Error reason: {error}</p>
            <p><a href="/?tab=gmail-shield" style="color:#38bdf8;">Return to SecureMailAnalyzer Dashboard</a></p>
        </body>
        </html>
        """, 400

    # Strict OAuth CSRF state verification (prevents login CSRF and state replay)
    if not state or not validate_and_consume_oauth_state(state):
        return """
        <html>
        <body style="background:#090d16;color:#f87171;font-family:sans-serif;padding:40px;text-align:center;">
            <h2>OAuth CSRF State Verification Failed</h2>
            <p>The authorization state token was missing, invalid, or expired. Please re-initiate connection from the dashboard.</p>
            <p><a href="/?tab=gmail-shield" style="color:#38bdf8;">Return to SecureMailAnalyzer Dashboard</a></p>
        </body>
        </html>
        """, 400

    if not code:
        return "Missing authorization code.", 400

    ok, msg, profile = exchange_code_for_tokens(code)
    if not ok:
        return f"""
        <html>
        <body style="background:#090d16;color:#f87171;font-family:sans-serif;padding:40px;text-align:center;">
            <h2>Token Exchange Error</h2>
            <p>{msg}</p>
            <p><a href="/?tab=gmail-shield" style="color:#38bdf8;">Return to Dashboard</a></p>
        </body>
        </html>
        """, 400

    email = profile.get("email", "connected account") if profile else "Gmail"
    return f"""
    <html>
    <head><title>Gmail Connected - SecureMailAnalyzer</title></head>
    <body style="background:#090d16;color:#f8fafc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:90vh;text-align:center;">
        <div style="background:#0f172a;border:1px solid #1e293b;border-radius:16px;padding:32px;max-width:480px;box-shadow:0 20px 25px -5px rgba(0,0,0,0.5);">
            <div style="width:48px;height:48px;background:rgba(6,182,212,0.1);border:1px solid #06b6d4;border-radius:12px;margin:0 auto 16px;display:flex;align-items:center;justify-content:center;">
                <span style="color:#06b6d4;font-size:24px;">✓</span>
            </div>
            <h2 style="margin:0 0 8px;font-size:20px;color:#fff;">Gmail Connected Successfully!</h2>
            <p style="color:#94a3b8;font-size:13px;line-height:1.5;">Account <strong>{email}</strong> is now securely connected for pre-download threat inspection.</p>
            <p style="color:#64748b;font-size:11px;margin-top:16px;">This window can be closed, or click below to return.</p>
            <a href="/?tab=gmail-shield" style="display:inline-block;margin-top:12px;background:#06b6d4;color:#090d16;padding:10px 20px;border-radius:8px;font-weight:600;text-decoration:none;font-size:13px;">Open SecureMailAnalyzer</a>
        </div>
        <script>
            if (window.opener) {{
                window.opener.postMessage({{ type: 'GMAIL_AUTH_SUCCESS', email: '{email}' }}, window.location.origin);
                setTimeout(() => window.close(), 2500);
            }}
        </script>
    </body>
    </html>
    """


@app.route("/api/gmail/disconnect", methods=["POST"])
def gmail_disconnect():
    """Disconnect active Gmail OAuth session."""
    ok_origin, err_origin = verify_origin_protection()
    if not ok_origin:
        return jsonify({"error": err_origin}), 403

    clear_gmail_token()
    return jsonify({
        "message": "Gmail integration disconnected successfully.",
        "status": get_gmail_connection_status(),
    })


@app.route("/api/gmail/messages", methods=["GET"])
def gmail_list_messages():
    """Retrieve list of recent Gmail messages containing attachments."""
    query = request.args.get("query", "has:attachment")
    max_results = min(int(request.args.get("max_results", 20)), 50)
    ok, msg, messages = list_messages_with_attachments(max_results=max_results, query=query)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify({"messages": messages, "count": len(messages)})


@app.route("/api/gmail/messages/<msg_id>", methods=["GET"])
def gmail_message_detail(msg_id: str):
    """Retrieve full message metadata and list of attached files."""
    ok, msg, details = get_message_attachments_metadata(msg_id)
    if not ok:
        return jsonify({"error": msg}), 400
    return jsonify(details)


@app.route("/api/gmail/messages/<msg_id>/attachments/<attachment_id>/analyze", methods=["POST"])
def analyze_gmail_attachment(msg_id: str, attachment_id: str):
    """Retrieve attachment bytes directly from Gmail API in memory and run static analysis."""
    # 1. Fetch message metadata to record subject and sender
    ok_meta, _, msg_meta = get_message_attachments_metadata(msg_id)
    subject = msg_meta.get("subject", "Gmail Attachment") if ok_meta else "Gmail Attachment"
    sender = msg_meta.get("sender", "Unknown Sender") if ok_meta else "Unknown Sender"

    # Identify attachment filename from message metadata if available
    filename = "gmail_attachment.bin"
    part_id = None
    if ok_meta and "attachments" in msg_meta:
        for att in msg_meta["attachments"]:
            if att.get("attachment_id") == attachment_id:
                filename = att.get("filename", filename)
                part_id = att.get("part_id")
                break

    # 2. Retrieve attachment bytes directly via authorized Gmail API (Zero download to user disk!)
    ok_bytes, err_msg, raw_bytes = retrieve_attachment_bytes(msg_id, attachment_id)
    if not ok_bytes or not raw_bytes:
        return jsonify({"error": f"Failed to retrieve attachment from Gmail: {err_msg}"}), 400

    # 3. Execute bounded static analysis pipeline
    analysis = analyze_file(filename, raw_bytes, filename)
    if "error" in analysis:
        return jsonify({"error": analysis["error"]}), 400

    # 4. Deterministic explainable risk evaluation
    risk_result = evaluate_risk(analysis["findings"])
    inv_id = f"SMA-GMAIL-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

    # 5. Evaluate pre-download policy enforcement decision
    enforce_decision, enforce_reason, _ = evaluate_enforcement_decision(
        risk_score=risk_result["risk_score"],
        severity=risk_result["severity"],
        sha256=analysis["sha256"],
        investigation_id=inv_id,
    )

    # 6. Build chronological Threat Story timeline
    timeline_events = generate_initial_threat_story(
        filename=analysis["filename"],
        original_filename=analysis["original_filename"],
        file_size=analysis["file_size"],
        file_extension=analysis["file_extension"],
        detected_format=analysis["detected_format"],
        sha256=analysis["sha256"],
        findings=risk_result["annotated_findings"],
        risk_score=risk_result["risk_score"],
        severity=risk_result["severity"],
        verdict=risk_result["verdict"],
        is_synthetic_sample=False,
    )

    # Append Gmail API Ingestion event to Threat Story
    timeline_events.insert(0, {
        "id": str(uuid.uuid4()),
        "event_type": "GMAIL_API_INGESTION",
        "title": "Attachment Retrieved via Authorized Gmail API",
        "description": f"Retrieved in-memory from message '{subject}' (Sender: {sender}). Ingested without local download.",
        "source": "Observed",
        "severity": "LOW",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "gmail_message_id": msg_id,
            "gmail_attachment_id": attachment_id,
            "gmail_part_id": part_id,
            "sender": sender,
            "subject": subject,
            "retrieval_method": "Google Gmail API v1 (Zero-disk in-memory buffer)",
        },
    })

    # Append Pre-Download Enforcement event to Threat Story
    timeline_events.append({
        "id": str(uuid.uuid4()),
        "event_type": "PRE_DOWNLOAD_ENFORCEMENT",
        "title": f"Pre-Download Policy Decision: {enforce_decision}",
        "description": enforce_reason,
        "source": "Application Action",
        "severity": risk_result["severity"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "enforcement_action": enforce_decision,
            "reason": enforce_reason,
            "policy_rule": "High/Critical (>50) automatically blocked; Low/Med permitted under review",
        },
    })

    # 7. Persist to SQLite
    save_investigation(
        inv_id=inv_id,
        filename=analysis["filename"],
        original_filename=analysis["original_filename"],
        file_size=analysis["file_size"],
        file_extension=analysis["file_extension"],
        detected_format=analysis["detected_format"],
        sha256=analysis["sha256"],
        risk_score=risk_result["risk_score"],
        severity=risk_result["severity"],
        verdict=risk_result["verdict"],
        findings=risk_result["annotated_findings"],
        limitations=analysis["limitations"],
        is_synthetic_sample=False,
        timeline_events=timeline_events,
        source_type="GMAIL_API",
        gmail_message_id=msg_id,
        gmail_attachment_id=attachment_id,
        gmail_part_id=part_id,
        gmail_sender=sender,
        gmail_subject=subject,
        enforcement_decision=enforce_decision,
    )

    full_record = get_investigation(inv_id)
    if full_record:
        full_record["risk_evaluation"] = risk_result
        full_record["enforcement"] = {
            "decision": enforce_decision,
            "reason": enforce_reason,
            "is_blocked": enforce_decision == "BLOCKED",
        }
        return jsonify(full_record), 201

    return jsonify({"error": "Failed to persist investigation record."}), 500


# =====================================================================
# BROWSER EXTENSION & PRE-DOWNLOAD ENFORCEMENT ENDPOINTS
# =====================================================================

@app.route("/api/extension/status", methods=["GET"])
def extension_status():
    """Heartbeat check and active policy parameters for the browser extension."""
    return jsonify({
        "status": "ONLINE",
        "service": "SecureMailAnalyzer Pre-Download Protection Service",
        "version": "1.2.0",
        "policy": {
            "blocking_threshold": 50,
            "critical_threshold": 75,
            "mode": "STRICT_ENFORCEMENT",
            "fail_closed": True,
            "supported_domains": ["mail.google.com"],
        },
        "gmail_session": get_gmail_connection_status(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/extension/check", methods=["POST"])
def extension_check_download():
    """Verify enforcement policy decision for an attachment download interaction.
    Fails closed: unanalyzed or untrusted attachments return PENDING_ANALYSIS (blocked from download).
    """
    data = request.get_json() or {}
    filename = data.get("filename", "").strip() or "attachment"
    sha256 = data.get("sha256", "").strip() or None
    gmail_message_id = data.get("gmail_message_id", "").strip() or None
    gmail_attachment_id = data.get("gmail_attachment_id", "").strip() or None
    gmail_part_id = data.get("gmail_part_id", "").strip() or None
    download_url = data.get("download_url", "").strip() or None
    release_token = data.get("release_token", "").strip() or None

    # Parse query parameters from download_url if IDs not explicitly supplied
    if download_url and (not gmail_message_id or not gmail_part_id):
        try:
            parsed = urllib.parse.urlparse(download_url)
            qs = urllib.parse.parse_qs(parsed.query)
            if not gmail_message_id and "th" in qs:
                gmail_message_id = qs["th"][0]
            if not gmail_part_id and "attid" in qs:
                gmail_part_id = qs["attid"][0]
        except Exception:
            pass

    client_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")

    result = check_attachment_enforcement_status(
        filename=filename,
        sha256=sha256,
        gmail_message_id=gmail_message_id,
        gmail_attachment_id=gmail_attachment_id,
        gmail_part_id=gmail_part_id,
        release_token=release_token,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    return jsonify(result)


@app.route("/api/extension/release", methods=["POST"])
def extension_release_attachment():
    """Execute an auditable authorized release for a blocked attachment."""
    ok_origin, err_origin = verify_origin_protection()
    if not ok_origin:
        return jsonify({"error": err_origin}), 403

    data = request.get_json() or {}
    inv_id = data.get("investigation_id", "").strip()
    authorized_by = data.get("authorized_by", "").strip()
    reason = data.get("reason", "").strip()

    if not inv_id:
        return jsonify({"error": "Investigation ID is required for release."}), 400
    if len(authorized_by) < 2:
        return jsonify({"error": "Authorized analyst identity is required (minimum 2 characters)."}), 400
    if len(reason) < 8:
        return jsonify({"error": "A documented security justification (minimum 8 characters) is required."}), 400

    try:
        release_res = execute_authorized_release(inv_id, authorized_by, reason)
        return jsonify(release_res)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": f"Internal release authorization error: {str(e)}"}), 500


@app.route("/api/extension/logs", methods=["GET"])
def extension_audit_logs():
    """Retrieve recent pre-download interception and enforcement audit logs."""
    limit = min(int(request.args.get("limit", 50)), 100)
    logs = list_enforcement_logs(limit=limit)
    return jsonify({"logs": logs, "count": len(logs)})


# Serve frontend static assets in production build
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path: str):
    dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "dist"))
    if os.path.exists(dist_dir):
        if path and os.path.exists(os.path.join(dist_dir, path)):
            return send_from_directory(dist_dir, path)
        return send_from_directory(dist_dir, "index.html")
    return jsonify({
        "message": "SecureMailAnalyzer Backend Active. Frontend build not yet generated.",
        "api_endpoints": [
            "/api/health",
            "/api/stats",
            "/api/analyze",
            "/api/investigations",
            "/api/samples",
            "/api/quarantine",
        ],
    })


if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" SecureMailAnalyzer — Backend Server Starting")
    print(" Local address: http://127.0.0.1:5000")
    print(" Mandatory Security: Bound to 127.0.0.1 (Localhost Only)")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=False)
