"""Comprehensive Unit and Integration Test Suite for SecureMailAnalyzer.
Verifies all 14 required security, analysis, scoring, timeline, and reporting features.
"""

import hashlib
import io
import json
import os
import sys
import unittest

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, backend_dir)

from analyzer import (
    MAX_FILE_SIZE,
    analyze_file,
    check_extension_mismatch,
    compute_sha256,
    detect_magic_signature,
    inspect_filename,
    sanitize_filename,
)
from database import (
    get_connection,
    get_dashboard_stats,
    get_investigation,
    get_quarantine_records,
    init_db,
    save_investigation,
    update_quarantine_status,
)
from report_generator import generate_csv_report, generate_json_report
from risk_engine import evaluate_risk, map_score_to_severity
from sandbox_parser import validate_and_parse_sandbox_report
from timeline import generate_initial_threat_story


class TestSecureMailAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    # 1. SHA-256 calculation
    def test_01_sha256_calculation(self):
        sample_bytes = b"Cybersecurity Hackathon 2026 Test Payload"
        expected_hash = hashlib.sha256(sample_bytes).hexdigest()
        computed_hash = compute_sha256(sample_bytes)
        self.assertEqual(computed_hash, expected_hash)
        self.assertEqual(len(computed_hash), 64)

    # 2. Analysis of a harmless text file
    def test_02_benign_text_file_analysis(self):
        benign_bytes = b"Hello, this is a legitimate plain text message without scripts."
        result = analyze_file("clean_notes.txt", benign_bytes)
        self.assertNotIn("error", result)
        self.assertEqual(result["file_extension"], ".txt")
        self.assertEqual(len(result["findings"]), 0)
        risk = evaluate_risk(result["findings"])
        self.assertEqual(risk["risk_score"], 0)
        self.assertEqual(risk["severity"], "LOW")

    # 3. Upload-size enforcement
    def test_03_upload_size_enforcement(self):
        oversized_bytes = b"A" * (MAX_FILE_SIZE + 1024)
        result = analyze_file("huge_archive.zip", oversized_bytes)
        self.assertIn("error", result)
        self.assertIn("exceeds maximum allowed limit", result["error"])

    # 4. Safe extension/signature mismatch detection
    def test_04_extension_signature_mismatch(self):
        # Disguised executable named as .pdf
        fake_pdf_pe_bytes = b"MZ" + b"\x00" * 200
        result = analyze_file("important_contract.pdf", fake_pdf_pe_bytes)
        self.assertNotIn("error", result)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("RULE-EXT-MISMATCH-EXE", rule_ids)
        risk = evaluate_risk(result["findings"])
        self.assertGreaterEqual(risk["risk_score"], 75)
        self.assertEqual(risk["severity"], "CRITICAL")

    # 5. Graceful handling of unsupported or malformed files
    def test_05_graceful_handling_malformed_archive(self):
        # File declares .docx but contains random non-zip binary garbage
        corrupted_bytes = b"\x12\x34\x56\x78\x90\xab\xcd\xef" * 20
        result = analyze_file("broken_statement.docx", corrupted_bytes)
        self.assertNotIn("error", result)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("RULE-ARCHIVE-MALFORMED", rule_ids)

    # 6. Invalid sandbox JSON rejection
    def test_06_invalid_sandbox_json_rejection(self):
        # Malformed syntax
        is_valid, err, events, meta = validate_and_parse_sandbox_report("{invalid_json: true,")
        self.assertFalse(is_valid)
        self.assertIn("Invalid JSON", err)

        # Missing required events array
        is_valid, err, events, meta = validate_and_parse_sandbox_report({"summary": "no events key"})
        self.assertFalse(is_valid)
        self.assertIn("Missing required 'events' array", err)

        # Empty events array
        is_valid, err, events, meta = validate_and_parse_sandbox_report({"events": []})
        self.assertFalse(is_valid)
        self.assertIn("contains no events", err)

    # 7. Valid sandbox event parsing and source attribution
    def test_07_valid_sandbox_event_parsing_and_attribution(self):
        valid_json = {
            "sandbox_metadata": {
                "report_version": "1.0",
                "analyzer_version": "Test-Cuckoo-Sandbox",
                "execution_time_seconds": 30,
            },
            "events": [
                {
                    "timestamp": "2026-10-10T12:00:00Z",
                    "category": "process_creation",
                    "event_title": "Spawned PowerShell with Hidden Flag",
                    "severity": "HIGH",
                    "description": "powershell.exe -w hidden",
                    "details": {"pid": 2040, "cmd": "powershell.exe -w hidden"},
                },
                {
                    "timestamp": "2026-10-10T12:00:05Z",
                    "category": "network_connection",
                    "event_title": "Outbound DNS Beacon",
                    "severity": "MEDIUM",
                    "description": "DNS query to malicious C2 domain",
                    "details": {"destination_ip": "198.51.100.1"},
                },
            ],
        }
        is_valid, err, events, meta = validate_and_parse_sandbox_report(valid_json)
        self.assertTrue(is_valid)
        self.assertEqual(len(events), 2)
        for ev in events:
            # Source must strictly be "Imported Sandbox Report"
            self.assertEqual(ev["source"], "Imported Sandbox Report")

    # 8. Risk score boundaries and severity mapping
    def test_08_risk_score_boundaries_and_severity_mapping(self):
        self.assertEqual(map_score_to_severity(0)[0], "LOW")
        self.assertEqual(map_score_to_severity(24)[0], "LOW")
        self.assertEqual(map_score_to_severity(25)[0], "MEDIUM")
        self.assertEqual(map_score_to_severity(49)[0], "MEDIUM")
        self.assertEqual(map_score_to_severity(50)[0], "HIGH")
        self.assertEqual(map_score_to_severity(74)[0], "HIGH")
        self.assertEqual(map_score_to_severity(75)[0], "CRITICAL")
        self.assertEqual(map_score_to_severity(100)[0], "CRITICAL")

    # 9. JSON report generation
    def test_09_json_report_generation(self):
        mock_inv = {
            "id": "SMA-TEST-001",
            "created_at": "2026-10-10T12:00:00Z",
            "original_filename": "invoice.pdf.bat",
            "file_size": 1024,
            "file_extension": ".bat",
            "detected_format": "Script",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "risk_score": 85,
            "severity": "CRITICAL",
            "verdict": "MALICIOUS / HIGH-CONFIDENCE SUSPICIOUS",
            "quarantine_status": "QUARANTINED",
            "quarantine_notes": "Immediate containment",
            "findings": [{"rule_id": "RULE-DOUBLE-EXT", "title": "Double Ext", "weight": 40, "contribution": 40}],
            "timeline": [{"event_type": "SUBMISSION", "title": "File Ingested", "source": "Application Action", "timestamp": "2026-10-10T12:00:00Z"}],
            "limitations": ["Bounded inspection"],
            "quarantine_history": [],
        }
        json_report_str = generate_json_report(mock_inv)
        parsed = json.loads(json_report_str)
        self.assertEqual(parsed["investigation_summary"]["investigation_id"], "SMA-TEST-001")
        self.assertEqual(parsed["investigation_summary"]["risk_score"], 85)
        self.assertIn("scoring_methodology", parsed)

    # 10. CSV export
    def test_10_csv_export_generation(self):
        mock_inv = {
            "id": "SMA-TEST-002",
            "created_at": "2026-10-10T12:00:00Z",
            "original_filename": "sample.pdf",
            "file_size": 2048,
            "file_extension": ".pdf",
            "detected_format": "Adobe PDF",
            "sha256": "a" * 64,
            "risk_score": 55,
            "severity": "HIGH",
            "verdict": "SUSPICIOUS",
            "quarantine_status": "ACTIVE",
            "findings": [{"rule_id": "RULE-PDF-JS", "title": "JS Action", "severity": "HIGH", "weight": 35, "contribution": 35, "explanation": "JS", "evidence": "/JS"}],
            "timeline": [{"timestamp": "2026-10-10T12:00:00Z", "source": "Observed", "severity": "HIGH", "title": "JS Found", "description": "Found JS"}],
        }
        csv_str = generate_csv_report(mock_inv)
        self.assertIn("SMA-TEST-002", csv_str)
        self.assertIn("RULE-PDF-JS", csv_str)
        self.assertIn("Observed", csv_str)

    # 11. Quarantine simulation state changes
    def test_11_quarantine_simulation_state_changes(self):
        import uuid
        inv_id = f"SMA-TEST-Q-{uuid.uuid4().hex[:8]}"
        save_investigation(
            inv_id=inv_id,
            filename="test_q.exe",
            original_filename="test_q.exe",
            file_size=500,
            file_extension=".exe",
            detected_format="Windows PE",
            sha256="b" * 64,
            risk_score=90,
            severity="CRITICAL",
            verdict="MALICIOUS",
            findings=[],
            limitations=[],
        )

        # Simulate Quarantine
        success = update_quarantine_status(inv_id, "QUARANTINED", "Analyst quarantine test", "Analyst-1")
        self.assertTrue(success)
        rec = get_investigation(inv_id)
        self.assertEqual(rec["quarantine_status"], "QUARANTINED")
        self.assertEqual(rec["quarantine_notes"], "Analyst quarantine test")

        # Simulate Restoration
        success_restore = update_quarantine_status(inv_id, "RESTORED", "Approved after second opinion", "Analyst-2")
        self.assertTrue(success_restore)
        rec_restored = get_investigation(inv_id)
        self.assertEqual(rec_restored["quarantine_status"], "RESTORED")

    # 12. Dashboard statistics derived from real records
    def test_12_dashboard_statistics(self):
        stats = get_dashboard_stats()
        self.assertIn("total_analyzed", stats)
        self.assertIn("severity_counts", stats)
        self.assertIn("quarantined_count", stats)
        self.assertIn("recent_investigations", stats)
        self.assertIn("risk_distribution", stats)
        self.assertIsInstance(stats["total_analyzed"], int)
        self.assertGreaterEqual(stats["total_analyzed"], 1)

    # 13. Error handling and missing-file cases
    def test_13_missing_investigation_and_error_handling(self):
        missing = get_investigation("SMA-NON-EXISTENT-ID-9999")
        self.assertIsNone(missing)

        # Empty string sanitization
        safe_name = sanitize_filename("../../etc/passwd")
        self.assertEqual(safe_name, "passwd")
        self.assertNotIn("/", safe_name)
        self.assertNotIn("..", safe_name)

    # 14. Confirmation that uploaded files are never executed
    def test_14_no_code_execution_guarantee(self):
        # We submit a batch script containing an echo command
        script_payload = b"@echo off\necho HARMFUL_COMMAND_ATTEMPT > hackathon_test_marker.txt\n"
        result = analyze_file("script.bat", script_payload)
        self.assertNotIn("error", result)
        # Verify that marker file was NEVER written/executed on the filesystem
        self.assertFalse(os.path.exists("hackathon_test_marker.txt"))


if __name__ == "__main__":
    unittest.main()
