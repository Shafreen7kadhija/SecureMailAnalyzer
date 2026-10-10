"""Unit and Integration Test Suite for Gmail Integration & Pre-Download Enforcement.
Verifies OAuth token lifecycle, policy decision logic, fail-closed handling,
repeat click bypass prevention, zero-download memory buffer, and auditable release workflows.
"""

import os
import sys
import unittest
import uuid

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, backend_dir)

from datetime import datetime, timedelta, timezone

from app import app
from analyzer import analyze_file
from database import (
    clear_gmail_token,
    create_oauth_state,
    create_release_authorization,
    find_investigation_by_identity,
    get_active_gmail_token,
    get_connection,
    get_investigation,
    init_db,
    is_attachment_released,
    list_enforcement_logs,
    log_enforcement_event,
    redeem_release_authorization,
    save_gmail_token,
    save_investigation,
    validate_and_consume_oauth_state,
)
from enforcement_engine import (
    check_attachment_enforcement_status,
    evaluate_enforcement_decision,
    execute_authorized_release,
)
from gmail_service import (
    generate_auth_url,
    get_gmail_connection_status,
    get_valid_access_token,
    save_oauth_config,
)
from risk_engine import evaluate_risk


class TestGmailEnforcementSuite(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        clear_gmail_token()

    # 1. Verification of OAuth URL generation & configuration
    def test_01_oauth_url_generation(self):
        save_oauth_config("mock_client_id_123.apps.googleusercontent.com", "mock_client_secret_xyz")
        ok, auth_url = generate_auth_url(state="test_state_123")
        self.assertTrue(ok)
        self.assertIn("https://accounts.google.com/o/oauth2/v2/auth", auth_url)
        self.assertIn("mock_client_id_123", auth_url)
        self.assertIn("test_state_123", auth_url)
        self.assertIn("gmail.readonly", auth_url)

    # 2. Token storage and retrieval lifecycle
    def test_02_gmail_token_storage_lifecycle(self):
        save_gmail_token(
            email="analyst@soc-test.org",
            access_token="mock_access_token_abc",
            refresh_token="mock_refresh_token_def",
            token_expiry="2099-01-01T00:00:00Z",
            scope="https://www.googleapis.com/auth/gmail.readonly",
        )
        token_data = get_active_gmail_token()
        self.assertIsNotNone(token_data)
        self.assertEqual(token_data["email"], "analyst@soc-test.org")
        self.assertEqual(token_data["access_token"], "mock_access_token_abc")

        # Status check
        status = get_gmail_connection_status()
        self.assertTrue(status["connected"])
        self.assertEqual(status["email"], "analyst@soc-test.org")

        # Disconnect
        clear_gmail_token()
        status_after = get_gmail_connection_status()
        self.assertFalse(status_after["connected"])

    # 3. High-risk and critical attachments are blocked by policy
    def test_03_high_and_critical_blocked_by_policy(self):
        # Critical score 85
        decision_crit, reason_crit, is_blocked_crit = evaluate_enforcement_decision(
            risk_score=85, severity="CRITICAL"
        )
        self.assertEqual(decision_crit, "BLOCKED")
        self.assertTrue(is_blocked_crit)
        self.assertIn("Pre-download blocked", reason_crit)

        # High score 60
        decision_high, reason_high, is_blocked_high = evaluate_enforcement_decision(
            risk_score=60, severity="HIGH"
        )
        self.assertEqual(decision_high, "BLOCKED")
        self.assertTrue(is_blocked_high)

    # 4. Low risk attachment allowed under policy
    def test_04_low_risk_allowed_by_policy(self):
        decision_low, reason_low, is_blocked_low = evaluate_enforcement_decision(
            risk_score=0, severity="LOW"
        )
        self.assertEqual(decision_low, "ALLOWED")
        self.assertFalse(is_blocked_low)

    # 5. Fail-closed: Pending/unanalyzed attachment is blocked from download
    def test_05_fail_closed_on_unscanned_attachment(self):
        # Attachment has never been submitted or analyzed
        result = check_attachment_enforcement_status(
            filename="unknown_unscanned_invoice.exe",
            sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )
        self.assertEqual(result["status"], "PENDING_ANALYSIS")
        self.assertEqual(result["enforcement_decision"], "BLOCKED")
        self.assertTrue(result["is_blocked"])
        self.assertIn("pending", result["reason"].lower())

    # 6. Attachment verdicts cannot be reused based solely on filename
    def test_06_no_verdict_reuse_by_filename_alone(self):
        # Create an investigation for clean file "statement.pdf"
        clean_inv_id = f"SMA-TEST-CLEAN-{uuid.uuid4().hex[:6]}"
        clean_hash = "1111111111111111111111111111111111111111111111111111111111111111"
        save_investigation(
            inv_id=clean_inv_id,
            filename="statement.pdf",
            original_filename="statement.pdf",
            file_size=1024,
            file_extension=".pdf",
            detected_format="Adobe PDF",
            sha256=clean_hash,
            risk_score=0,
            severity="LOW",
            verdict="BENIGN",
            findings=[],
            limitations=[],
        )

        # Now an unanalyzed file arrives with the SAME filename "statement.pdf", but DIFFERENT hash
        diff_hash = "2222222222222222222222222222222222222222222222222222222222222222"
        check_result = check_attachment_enforcement_status(
            filename="statement.pdf",
            sha256=diff_hash,
        )
        # Must NOT inherit the clean verdict! Must fail-closed as pending analysis!
        self.assertEqual(check_result["status"], "PENDING_ANALYSIS")
        self.assertTrue(check_result["is_blocked"])

    # 7. Repeating blocked download does not bypass policy and increments repeat counter
    def test_07_repeat_click_bypass_prevention(self):
        blocked_inv_id = f"SMA-TEST-BLOCK-{uuid.uuid4().hex[:6]}"
        bad_hash = "9999999999999999999999999999999999999999999999999999999999999999"
        save_investigation(
            inv_id=blocked_inv_id,
            filename="invoice.pdf.bat",
            original_filename="invoice.pdf.bat",
            file_size=500,
            file_extension=".bat",
            detected_format="Script",
            sha256=bad_hash,
            risk_score=85,
            severity="CRITICAL",
            verdict="MALICIOUS",
            findings=[],
            limitations=[],
        )

        # First click attempt
        res1 = check_attachment_enforcement_status(
            filename="invoice.pdf.bat",
            sha256=bad_hash,
        )
        self.assertEqual(res1["enforcement_decision"], "BLOCKED")
        self.assertTrue(res1["is_blocked"])

        # Second click attempt (user attempts to repeat action)
        res2 = check_attachment_enforcement_status(
            filename="invoice.pdf.bat",
            sha256=bad_hash,
        )
        self.assertEqual(res2["enforcement_decision"], "BLOCKED")
        self.assertTrue(res2["is_blocked"])

        # Third click attempt
        res3 = check_attachment_enforcement_status(
            filename="invoice.pdf.bat",
            sha256=bad_hash,
        )
        self.assertEqual(res3["enforcement_decision"], "BLOCKED")
        self.assertTrue(res3["is_blocked"])

        # Check that enforcement audit logs captured repeat attempts
        logs = list_enforcement_logs(limit=10)
        matching = [l for l in logs if l["filename"] == "invoice.pdf.bat" and l["action"] == "BLOCKED"]
        self.assertGreater(len(matching), 0)
        self.assertGreaterEqual(matching[0]["repeat_count"], 1)

    # 8. Authorized release workflow creates auditable token and permits release
    def test_08_authorized_release_workflow(self):
        rel_inv_id = f"SMA-TEST-REL-{uuid.uuid4().hex[:6]}"
        rel_hash = f"relhash_{uuid.uuid4().hex}"
        save_investigation(
            inv_id=rel_inv_id,
            filename="quarantine_candidate.docm",
            original_filename="quarantine_candidate.docm",
            file_size=4096,
            file_extension=".docm",
            detected_format="Office Macro",
            sha256=rel_hash,
            risk_score=65,
            severity="HIGH",
            verdict="SUSPICIOUS",
            findings=[],
            limitations=[],
        )

        # Before release, status is BLOCKED
        before_check = check_attachment_enforcement_status(
            filename="quarantine_candidate.docm",
            sha256=rel_hash,
        )
        self.assertEqual(before_check["enforcement_decision"], "BLOCKED")
        self.assertTrue(before_check["is_blocked"])

        # Execute authorized security release override
        rel_res = execute_authorized_release(
            investigation_id=rel_inv_id,
            authorized_by="Lead Analyst John",
            reason="Verified document legitimacy directly with corporate finance VP.",
        )
        self.assertTrue(rel_res["success"])
        self.assertEqual(rel_res["enforcement_decision"], "RELEASED")
        self.assertFalse(rel_res["is_blocked"])
        self.assertTrue(rel_res["release"]["auth_token"].startswith("REL-"))

        # After release, policy check returns RELEASED and permits download
        after_check = check_attachment_enforcement_status(
            filename="quarantine_candidate.docm",
            sha256=rel_hash,
        )
        self.assertEqual(after_check["enforcement_decision"], "RELEASED")
        self.assertFalse(after_check["is_blocked"])
        self.assertTrue(after_check["is_released"])

    # 9. Release validation requires mandatory analyst name and justification
    def test_09_release_validation_rejection(self):
        dummy_inv_id = f"SMA-DUMMY-{uuid.uuid4().hex[:6]}"
        save_investigation(
            inv_id=dummy_inv_id,
            filename="test.exe",
            original_filename="test.exe",
            file_size=100,
            file_extension=".exe",
            detected_format="PE",
            sha256="dummy_hash_123",
            risk_score=90,
            severity="CRITICAL",
            verdict="MALICIOUS",
            findings=[],
            limitations=[],
        )

        # Missing analyst name
        with self.assertRaises(ValueError):
            execute_authorized_release(dummy_inv_id, "", "Valid justification reason here")

        # Justification too short (< 8 chars)
        with self.assertRaises(ValueError):
            execute_authorized_release(dummy_inv_id, "Analyst", "short")

    # 10. Strict Identity Matching via compound keys (message_id + part_id, attachment_id, SHA-256)
    def test_10_identity_matching_compound_keys_and_part_id(self):
        inv_id = f"SMA-TEST-ID-{uuid.uuid4().hex[:6]}"
        sha = "3333333333333333333333333333333333333333333333333333333333333333"
        msg_id = "msg_identity_test_123"
        att_id = "att_identity_test_456"
        part_id = "0.2"

        save_investigation(
            inv_id=inv_id,
            filename="financial_summary.xlsx",
            original_filename="financial_summary.xlsx",
            file_size=2048,
            file_extension=".xlsx",
            detected_format="OpenXML Spreadsheet",
            sha256=sha,
            risk_score=75,
            severity="CRITICAL",
            verdict="MALICIOUS",
            findings=[],
            limitations=[],
            gmail_message_id=msg_id,
            gmail_attachment_id=att_id,
            gmail_part_id=part_id,
        )

        # Match 1: Message ID + Part ID
        match_part = find_investigation_by_identity(gmail_message_id=msg_id, gmail_part_id=part_id)
        self.assertIsNotNone(match_part)
        self.assertEqual(match_part["id"], inv_id)

        # Match 2: Message ID + Attachment ID
        match_att = find_investigation_by_identity(gmail_message_id=msg_id, gmail_attachment_id=att_id)
        self.assertIsNotNone(match_att)
        self.assertEqual(match_att["id"], inv_id)

        # Match 3: Exact SHA-256
        match_hash = find_investigation_by_identity(sha256=sha)
        self.assertIsNotNone(match_hash)
        self.assertEqual(match_hash["id"], inv_id)

        # Mismatch: Incorrect part ID under same message ID
        no_match = find_investigation_by_identity(gmail_message_id=msg_id, gmail_part_id="0.99")
        self.assertIsNone(no_match)

    # 11. Filename-only queries fail-closed without reliable compound identity
    def test_11_filename_only_queries_fail_closed(self):
        # Even if a file named 'report.pdf' exists in database, query without hash or message_id returns None
        inv_id = f"SMA-TEST-NAME-{uuid.uuid4().hex[:6]}"
        save_investigation(
            inv_id=inv_id,
            filename="corporate_budget.pdf",
            original_filename="corporate_budget.pdf",
            file_size=1024,
            file_extension=".pdf",
            detected_format="Adobe PDF",
            sha256="4444444444444444444444444444444444444444444444444444444444444444",
            risk_score=10,
            severity="LOW",
            verdict="BENIGN",
            findings=[],
            limitations=[],
        )

        # Strict lookup with filename only must be rejected to prevent filename spoofing
        lookup = find_investigation_by_identity(filename="corporate_budget.pdf")
        self.assertIsNone(lookup)

        # Policy check with filename only fails closed as PENDING_ANALYSIS / BLOCKED
        status = check_attachment_enforcement_status(filename="corporate_budget.pdf")
        self.assertEqual(status["status"], "PENDING_ANALYSIS")
        self.assertEqual(status["enforcement_decision"], "BLOCKED")
        self.assertTrue(status["is_blocked"])

    # 12. OAuth CSRF State Token Generation, Expiration, and Single-Use Consumption
    def test_12_oauth_state_generation_and_single_use_validation(self):
        # create_oauth_state accepts expiry_seconds (default 600)
        state = create_oauth_state(expiry_seconds=600)
        self.assertTrue(isinstance(state, str))
        self.assertGreaterEqual(len(state), 32)

        # First consumption must succeed
        valid_first = validate_and_consume_oauth_state(state)
        self.assertTrue(valid_first)

        # Second consumption of the same state MUST fail (single-use / replay prevention)
        valid_second = validate_and_consume_oauth_state(state)
        self.assertFalse(valid_second)

        # Non-existent random state must fail
        self.assertFalse(validate_and_consume_oauth_state("non_existent_random_state_999"))

        # Expired state must be rejected — insert a token already past expiry
        conn = get_connection()
        cursor = conn.cursor()
        expired_state = f"expired_state_token_test_{uuid.uuid4().hex[:8]}"
        past_iso = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        cursor.execute(
            "INSERT OR IGNORE INTO oauth_states (state, created_at, expires_at) VALUES (?, ?, ?)",
            (expired_state, past_iso, past_iso),
        )
        conn.commit()
        conn.close()

        self.assertFalse(validate_and_consume_oauth_state(expired_state))

    # 13. Release Token Entropy, 15-Minute Expiration, Single-Use Redemption, and Scoping
    def test_13_release_token_entropy_and_single_use_redemption(self):
        inv_id = f"SMA-TEST-REL-HARDEN-{uuid.uuid4().hex[:6]}"
        sha = "5555555555555555555555555555555555555555555555555555555555555555"
        save_investigation(
            inv_id=inv_id,
            filename="blocked_script.vbs",
            original_filename="blocked_script.vbs",
            file_size=512,
            file_extension=".vbs",
            detected_format="Visual Basic Script",
            sha256=sha,
            risk_score=80,
            severity="CRITICAL",
            verdict="MALICIOUS",
            findings=[],
            limitations=[],
            gmail_message_id="msg_rel_test",
            gmail_attachment_id="att_rel_test",
        )

        # create_release_authorization only accepts: investigation_id, authorized_by, reason, expiry_minutes
        auth_record = create_release_authorization(
            investigation_id=inv_id,
            authorized_by="Lead Security Analyst",
            reason="Confirmed internal benign administrative script.",
            expiry_minutes=15,
        )

        token = auth_record["auth_token"]
        self.assertTrue(token.startswith("REL-"))
        # Token format: REL- + token_urlsafe(24) = REL- (4) + 32 chars = 36+ chars
        self.assertGreaterEqual(len(token), 36)

        # Scope mismatch: attempt redemption for a different investigation
        ok_wrong_inv, msg_wrong, _ = redeem_release_authorization(
            token=token,
            investigation_id="SMA-DIFFERENT-INV-9999",
            sha256=sha,
        )
        self.assertFalse(ok_wrong_inv)
        # Actual message: "Release token was issued for a different investigation."
        self.assertIn("different investigation", msg_wrong.lower())

        # Scope mismatch: attempt redemption with wrong SHA-256
        ok_wrong_hash, msg_wrong_hash, _ = redeem_release_authorization(
            token=token,
            investigation_id=inv_id,
            sha256="wrong_hash_0000000000000000000000000000000000000000000000000000",
        )
        self.assertFalse(ok_wrong_hash)
        # Actual message: "Release token does not match attachment hash."
        self.assertIn("does not match", msg_wrong_hash.lower())

        # Valid single-use redemption
        ok_redeem, msg_redeem, rel_data = redeem_release_authorization(
            token=token,
            investigation_id=inv_id,
            sha256=sha,
        )
        self.assertTrue(ok_redeem)
        self.assertIn("successfully", msg_redeem.lower())

        # Second redemption attempt MUST fail (single-use enforced)
        ok_second, msg_second, _ = redeem_release_authorization(
            token=token,
            investigation_id=inv_id,
            sha256=sha,
        )
        self.assertFalse(ok_second)
        # Actual message: "Release token has already been redeemed (single-use enforcement)."
        self.assertIn("already been redeemed", msg_second.lower())

    # 14. API Host Header Validation (DNS Rebinding Defense)
    def test_14_api_host_header_validation(self):
        client = app.test_client()

        # Legitimate localhost Host header
        res_ok = client.get("/api/health", headers={"Host": "127.0.0.1:5000"})
        self.assertEqual(res_ok.status_code, 200)

        res_ok_lh = client.get("/api/health", headers={"Host": "localhost:5000"})
        self.assertEqual(res_ok_lh.status_code, 200)

        # Attacker DNS rebinding domain Host header
        res_bad = client.get("/api/health", headers={"Host": "evil-attacker-site.com"})
        self.assertEqual(res_bad.status_code, 400)
        self.assertIn("Invalid Host header", res_bad.get_json()["error"])

    # 15. CORS Origin Restrictions (no wildcard, explicit origins only)
    def test_15_cors_origin_restrictions(self):
        client = app.test_client()

        # Permitted local frontend origin
        res_allowed = client.get(
            "/api/health",
            headers={"Origin": "http://127.0.0.1:3000", "Host": "127.0.0.1:5000"},
        )
        self.assertEqual(res_allowed.status_code, 200)
        self.assertEqual(res_allowed.headers.get("Access-Control-Allow-Origin"), "http://127.0.0.1:3000")

        # Disallowed untrusted origin must NOT receive Access-Control-Allow-Origin
        res_disallowed = client.get(
            "/api/health",
            headers={"Origin": "https://malicious-website.com", "Host": "127.0.0.1:5000"},
        )
        self.assertEqual(res_disallowed.status_code, 200)
        self.assertNotEqual(res_disallowed.headers.get("Access-Control-Allow-Origin"), "https://malicious-website.com")
        self.assertNotEqual(res_disallowed.headers.get("Access-Control-Allow-Origin"), "*")

    # 16. Origin Protection on Sensitive State-Changing Endpoints
    def test_16_origin_protection_on_sensitive_endpoints(self):
        client = app.test_client()

        # Attacker origin attempting to trigger disconnect
        res_disc_bad = client.post(
            "/api/gmail/disconnect",
            headers={"Origin": "https://attacker.org", "Host": "127.0.0.1:5000"},
        )
        self.assertEqual(res_disc_bad.status_code, 403)
        self.assertIn("Cross-origin request rejected", res_disc_bad.get_json()["error"])

        # Attacker origin attempting to trigger emergency release
        res_rel_bad = client.post(
            "/api/extension/release",
            headers={"Origin": "https://attacker.org", "Host": "127.0.0.1:5000"},
            json={"investigation_id": "test", "authorized_by": "hacker", "reason": "bypass"},
        )
        self.assertEqual(res_rel_bad.status_code, 403)

        # Attacker origin attempting to toggle quarantine
        res_quar_bad = client.post(
            "/api/investigations/dummy/quarantine",
            headers={"Origin": "https://attacker.org", "Host": "127.0.0.1:5000"},
            json={"status": "RESTORED"},
        )
        self.assertEqual(res_quar_bad.status_code, 403)

        # Legitimate origin permitted through origin verification
        res_disc_good = client.post(
            "/api/gmail/disconnect",
            headers={"Origin": "http://127.0.0.1:3000", "Host": "127.0.0.1:5000"},
        )
        self.assertEqual(res_disc_good.status_code, 200)

    # 17. Same-Name Attachments Across Different Messages Fail-Closed and Never Cross-Contaminate
    def test_17_same_filename_different_messages_isolation(self):
        # Create malicious file 'invoice.pdf' in Message A
        msg_a = f"msg_a_{uuid.uuid4().hex[:6]}"
        inv_a = f"SMA-MSG-A-{uuid.uuid4().hex[:6]}"
        save_investigation(
            inv_id=inv_a,
            filename="invoice.pdf",
            original_filename="invoice.pdf",
            file_size=2048,
            file_extension=".pdf",
            detected_format="Adobe PDF",
            sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            risk_score=90,
            severity="CRITICAL",
            verdict="MALICIOUS",
            findings=[],
            limitations=[],
            gmail_message_id=msg_a,
            gmail_attachment_id="att_a",
            gmail_part_id="0.1",
        )

        # Create benign file 'invoice.pdf' in Message B
        msg_b = f"msg_b_{uuid.uuid4().hex[:6]}"
        inv_b = f"SMA-MSG-B-{uuid.uuid4().hex[:6]}"
        save_investigation(
            inv_id=inv_b,
            filename="invoice.pdf",
            original_filename="invoice.pdf",
            file_size=2048,
            file_extension=".pdf",
            detected_format="Adobe PDF",
            sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            risk_score=0,
            severity="LOW",
            verdict="BENIGN",
            findings=[],
            limitations=[],
            gmail_message_id=msg_b,
            gmail_attachment_id="att_b",
            gmail_part_id="0.1",
        )

        # Checking policy for Message A's invoice.pdf must return BLOCKED (CRITICAL)
        status_a = check_attachment_enforcement_status(
            filename="invoice.pdf",
            gmail_message_id=msg_a,
            gmail_part_id="0.1",
        )
        self.assertEqual(status_a["enforcement_decision"], "BLOCKED")
        self.assertTrue(status_a["is_blocked"])
        self.assertEqual(status_a["investigation_id"], inv_a)

        # Checking policy for Message B's invoice.pdf must return ALLOWED (LOW)
        status_b = check_attachment_enforcement_status(
            filename="invoice.pdf",
            gmail_message_id=msg_b,
            gmail_part_id="0.1",
        )
        self.assertEqual(status_b["enforcement_decision"], "ALLOWED")
        self.assertFalse(status_b["is_blocked"])
        self.assertEqual(status_b["investigation_id"], inv_b)

        # Querying with a non-existent Message C with the same filename 'invoice.pdf' MUST FAIL CLOSED
        msg_c = f"msg_c_{uuid.uuid4().hex[:6]}"
        status_c = check_attachment_enforcement_status(
            filename="invoice.pdf",
            gmail_message_id=msg_c,
            gmail_part_id="0.1",
        )
        self.assertEqual(status_c["status"], "PENDING_ANALYSIS")
        self.assertEqual(status_c["enforcement_decision"], "BLOCKED")
        self.assertTrue(status_c["is_blocked"])

    # 18. Release Token Scoping Enforces Part ID and Attachment ID Matching
    def test_18_release_token_part_id_and_attachment_id_scoping(self):
        inv_id = f"SMA-TEST-PART-SCOPE-{uuid.uuid4().hex[:6]}"
        sha = "8888888888888888888888888888888888888888888888888888888888888888"
        save_investigation(
            inv_id=inv_id,
            filename="multi_part_attachment.zip",
            original_filename="multi_part_attachment.zip",
            file_size=4096,
            file_extension=".zip",
            detected_format="ZIP Archive",
            sha256=sha,
            risk_score=75,
            severity="CRITICAL",
            verdict="MALICIOUS",
            findings=[],
            limitations=[],
            gmail_message_id="msg_multipart",
            gmail_attachment_id="att_part_1",
            gmail_part_id="0.2",
        )

        auth_record = create_release_authorization(
            investigation_id=inv_id,
            authorized_by="Lead SOC Auditor",
            reason="Verified safe nested analysis artifact.",
            expiry_minutes=15,
        )
        token = auth_record["auth_token"]

        # Attempt redemption with wrong part_id (e.g. "0.3" instead of "0.2")
        ok_wrong_part, msg_wrong_part, _ = redeem_release_authorization(
            token=token,
            investigation_id=inv_id,
            gmail_message_id="msg_multipart",
            gmail_part_id="0.3",
        )
        self.assertFalse(ok_wrong_part)
        self.assertIn("different attachment part", msg_wrong_part.lower())

        # Attempt redemption with wrong attachment_id
        ok_wrong_att, msg_wrong_att, _ = redeem_release_authorization(
            token=token,
            investigation_id=inv_id,
            gmail_message_id="msg_multipart",
            gmail_attachment_id="att_part_999",
        )
        self.assertFalse(ok_wrong_att)
        self.assertIn("different gmail attachment id", msg_wrong_att.lower())

        # Successful redemption with matching part_id and message_id
        ok_valid, msg_valid, _ = redeem_release_authorization(
            token=token,
            investigation_id=inv_id,
            gmail_message_id="msg_multipart",
            gmail_part_id="0.2",
            sha256=sha,
        )
        self.assertTrue(ok_valid)

    # 19. Empty or Missing Identifiers Always Fail Closed
    def test_19_empty_and_partial_identifiers_fail_closed(self):
        # Empty string / whitespace parameters
        status_empty = check_attachment_enforcement_status(
            filename="   ",
            gmail_message_id="",
            gmail_part_id="",
            sha256="",
        )
        self.assertEqual(status_empty["status"], "PENDING_ANALYSIS")
        self.assertTrue(status_empty["is_blocked"])

        # Mismatched part ID under known message returns PENDING_ANALYSIS (fail closed)
        status_mismatch = check_attachment_enforcement_status(
            filename="unknown.dat",
            gmail_message_id="msg_rel_test",
            gmail_part_id="999.999",
        )
        self.assertEqual(status_mismatch["status"], "PENDING_ANALYSIS")
        self.assertTrue(status_mismatch["is_blocked"])


if __name__ == "__main__":
    unittest.main()

