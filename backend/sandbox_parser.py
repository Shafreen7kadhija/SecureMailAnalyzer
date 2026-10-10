"""Sandbox JSON report parser and validator for SecureMailAnalyzer.
Safely extracts behavioral events from imported reports without executing or resolving anything.
"""

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Tuple

VALID_CATEGORIES = {
    "process_creation": "Process Creation",
    "network_connection": "Network Connection",
    "file_modification": "File Modification",
    "registry_persistence": "Registry / Persistence",
    "evasion_activity": "Defense Evasion",
    "generic": "General Behavioral Event"
}

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def validate_and_parse_sandbox_report(json_data: Any) -> Tuple[bool, str, List[Dict[str, Any]], Dict[str, Any]]:
    """Validate sandbox JSON structure and parse events.
    Returns: (is_valid, error_message, parsed_events, metadata)
    """
    if isinstance(json_data, str):
        try:
            data = json.loads(json_data)
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON syntax: {str(e)}", [], {}
    elif isinstance(json_data, dict):
        data = json_data
    else:
        return False, "Expected JSON object at top level.", [], {}

    # Check top-level events
    events_raw = data.get("events")
    if events_raw is None:
        return False, "Missing required 'events' array in sandbox report.", [], {}

    if not isinstance(events_raw, list):
        return False, "'events' field must be an array of event objects.", [], {}

    if len(events_raw) == 0:
        return False, "The 'events' array contains no events.", [], {}

    if len(events_raw) > 200:
        return False, f"Report exceeds event ceiling (maximum 200 events allowed, got {len(events_raw)}).", [], {}

    # Extract metadata safely
    metadata_raw = data.get("sandbox_metadata", {})
    if not isinstance(metadata_raw, dict):
        metadata_raw = {}

    metadata = {
        "report_version": str(metadata_raw.get("report_version", "1.0"))[:50],
        "analyzer_version": str(metadata_raw.get("analyzer_version", "Unknown Sandbox"))[:100],
        "analysis_environment": str(metadata_raw.get("analysis_environment", "Dynamic Sandbox Guest VM"))[:100],
        "execution_time_seconds": metadata_raw.get("execution_time_seconds", 0),
        "sample_sha256": str(metadata_raw.get("sample_sha256", "N/A"))[:64],
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": "Imported behavioral report provided by external sandbox. Not executed on host machine."
    }

    parsed_events: List[Dict[str, Any]] = []

    for idx, ev in enumerate(events_raw):
        if not isinstance(ev, dict):
            return False, f"Event at index {idx} is not a valid JSON object.", [], {}

        title = str(ev.get("event_title") or ev.get("title") or f"Behavioral Event #{idx + 1}")[:150]
        desc = str(ev.get("description") or ev.get("summary") or "Imported dynamic behavioral activity")[:500]
        category = str(ev.get("category", "generic")).lower()
        if category not in VALID_CATEGORIES:
            category = "generic"

        severity = str(ev.get("severity", "LOW")).upper()
        if severity not in VALID_SEVERITIES:
            severity = "MEDIUM" if "process" in category or "network" in category else "LOW"

        # Validate timestamp or fallback to current time with offset
        ts = ev.get("timestamp")
        parsed_ts = datetime.now(timezone.utc).isoformat()
        if ts and isinstance(ts, str):
            try:
                # Basic ISO validation
                clean_ts = ts.replace("Z", "+00:00")
                datetime.fromisoformat(clean_ts)
                parsed_ts = ts
            except Exception:
                pass  # Fall back to parsed_ts

        # Sanitize details dict
        raw_details = ev.get("details", {})
        details = {}
        if isinstance(raw_details, dict):
            for k, v in raw_details.items():
                k_clean = str(k)[:50]
                if isinstance(v, (str, int, float, bool)):
                    details[k_clean] = v if not isinstance(v, str) else v[:300]
                elif isinstance(v, list):
                    details[k_clean] = [str(item)[:100] for item in v[:10]]
        else:
            details = {"raw_info": str(raw_details)[:300]}

        parsed_events.append({
            "event_type": f"SANDBOX_{category.upper()}",
            "title": f"[{VALID_CATEGORIES[category]}] {title}",
            "description": desc,
            "source": "Imported Sandbox Report",
            "severity": severity,
            "timestamp": parsed_ts,
            "details": details,
        })

    return True, "", parsed_events, metadata
