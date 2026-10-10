"""Static File Analysis Pipeline for SecureMailAnalyzer.
Safely extracts file metadata, magic numbers, checks signatures, inspects bounded streams,
and flags suspicious indicators without executing any code.
"""

import hashlib
import io
import os
import re
import zipfile
from typing import Any, Dict, List, Optional, Tuple

MAX_FILE_SIZE = 25 * 1024 * 1024  # 25 MB max limit
MAX_BOUNDED_READ = 2 * 1024 * 1024  # 2 MB bounded inspection for strings/markers

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".ps1xml", ".ps2", ".psc1", ".psc2",
    ".scr", ".hta", ".cpl", ".jar", ".iso", ".img", ".lnk", ".pif",
    ".com", ".msp", ".msi", ".reg", ".bas"
}

OFFICE_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

# Magic byte signatures
SIGNATURES = [
    (b"MZ", "Windows PE Executable / DLL (MZ Header)"),
    (b"\x7fELF", "Linux Executable (ELF Header)"),
    (b"%PDF", "Adobe Portable Document Format (PDF)"),
    (b"PK\x03\x04", "ZIP Archive / OpenXML Document"),
    (b"PK\x05\x06", "Empty ZIP Archive"),
    (b"PK\x07\x08", "ZIP Spanned Archive"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "Microsoft Compound File Binary / OLE2 (Legacy Office)"),
    (b"7z\xBC\xAF\x27\x1C", "7-Zip Compressed Archive"),
    (b"Rar!\x1A\x07\x00", "RAR Archive v4"),
    (b"Rar!\x1A\x07\x01\x00", "RAR Archive v5"),
    (b"\x89PNG\r\n\x1a\n", "Portable Network Graphics (PNG) Image"),
    (b"\xff\xd8\xff", "JPEG Image"),
    (b"GIF87a", "GIF Image (87a)"),
    (b"GIF89a", "GIF Image (89a)"),
    (b"{\\rtf", "Rich Text Format (RTF)"),
]

SUSPICIOUS_STRING_PATTERNS = [
    (r"(?i)powershell(\.exe)?\s+(-[a-z0-9\-]+\s+)*(-enc|-encodedcommand)\b", "PowerShell Encoded Command execution pattern", "HIGH"),
    (r"(?i)powershell(\.exe)?\s+(-[a-z0-9\-]+\s+)*(-executionpolicy\s+bypass|-ep\s+bypass)\b", "PowerShell ExecutionPolicy Bypass switch", "HIGH"),
    (r"(?i)powershell(\.exe)?\s+(-[a-z0-9\-]+\s+)*(-w\s+hidden|-windowstyle\s+hidden)\b", "PowerShell Hidden Window Style execution flag", "HIGH"),
    (r"(?i)cmd(\.exe)?\s+/c\s+start\s+/min\b", "Command prompt invocation with minimized window switch", "MEDIUM"),
    (r"(?i)certutil(\.exe)?\s+(-urlcache|-decode|-decodehex)\b", "Certutil binary abuse pattern for payload downloading/decoding", "HIGH"),
    (r"(?i)bitsadmin(\.exe)?\s+/transfer\b", "BITSAdmin background transfer payload download pattern", "MEDIUM"),
    (r"(?i)wscript\.shell\b", "WScript.Shell object instantiation marker", "MEDIUM"),
    (r"(?i)rundll32(\.exe)?\s+[a-z0-9_\-\.\\]+,\w+", "Rundll32 dynamic link execution command", "HIGH"),
    (r"(?i)vssadmin(\.exe)?\s+delete\s+shadows\b", "Ransomware-associated volume shadow copy deletion command", "CRITICAL"),
]


def sanitize_filename(filename: str) -> str:
    """Safely sanitize uploaded filename to prevent directory traversal or control characters."""
    base = os.path.basename(filename.strip().replace("\\", "/"))
    # Remove null bytes or control characters
    base = "".join(c for c in base if c.isprintable() and c not in '<>:"/\\|?*')
    return base if base else "unnamed_attachment.bin"


def compute_sha256(file_bytes: bytes) -> str:
    """Compute SHA-256 hash using streaming hashlib."""
    h = hashlib.sha256()
    h.update(file_bytes)
    return h.hexdigest()


def detect_magic_signature(file_bytes: bytes) -> Tuple[str, str]:
    """Detect magic byte signature from initial bytes."""
    header = file_bytes[:16]
    for sig, label in SIGNATURES:
        if header.startswith(sig):
            return sig.hex(), label
    # Plain text heuristic
    try:
        sample = file_bytes[:512].decode("utf-8")
        if sample.isprintable() or any(c in "\r\n\t" for c in sample):
            return "text", "Plain Text / Script (UTF-8/ASCII)"
    except Exception:
        pass
    return "unknown", "Unknown Binary / Unidentified Format"


def inspect_filename(filename: str) -> List[Dict[str, Any]]:
    """Inspect filename for double extensions, RTL override, or deceptive patterns."""
    findings = []
    
    # Check Right-to-Left Override character (U+202E)
    if "\u202e" in filename:
        findings.append({
            "rule_id": "RULE-RTL-OVERRIDE",
            "title": "Right-to-Left Override Character Detected",
            "severity": "CRITICAL",
            "weight": 55,
            "explanation": "Adversaries use Unicode U+202E to visually invert extensions (e.g. making .exe appear as .pdf) to trick users into executing malicious files.",
            "evidence": f"Filename contains Unicode U+202E RTL marker: '{filename}'",
        })

    # Double extension check (e.g., invoice.pdf.exe or report.docx.vbs)
    parts = filename.lower().split(".")
    if len(parts) > 2:
        ext = f".{parts[-1]}"
        penultimate = f".{parts[-2]}"
        decoy_extensions = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".jpg", ".png", ".txt", ".mp4"}
        if penultimate in decoy_extensions and (ext in DANGEROUS_EXTENSIONS or ext in OFFICE_MACRO_EXTENSIONS):
            findings.append({
                "rule_id": "RULE-DOUBLE-EXTENSION",
                "title": "Suspicious Double Extension Pattern",
                "severity": "HIGH",
                "weight": 45,
                "explanation": "File uses a decoy document extension followed by an executable or script extension to deceive end-users.",
                "evidence": f"Decoy extension '{penultimate}' masquerading before actual extension '{ext}' in '{filename}'",
            })

    # Direct dangerous extension
    ext = os.path.splitext(filename)[1].lower()
    if ext in DANGEROUS_EXTENSIONS:
        findings.append({
            "rule_id": "RULE-DANGEROUS-EXT",
            "title": f"Potentially Dangerous File Extension Detected ({ext})",
            "severity": "HIGH",
            "weight": 40,
            "explanation": f"The '{ext}' file extension is an executable, script, or system shortcut commonly abused in phishing attacks.",
            "evidence": f"File declared with executable/script extension: {ext}",
        })

    if ext in OFFICE_MACRO_EXTENSIONS:
        findings.append({
            "rule_id": "RULE-MACRO-EXTENSION",
            "title": f"Macro-Enabled Office Document Extension ({ext})",
            "severity": "MEDIUM",
            "weight": 30,
            "explanation": "File extension designates a macro-enabled container capable of executing Visual Basic for Applications (VBA) code.",
            "evidence": f"File declares macro-enabled extension: {ext}",
        })

    return findings


def check_extension_mismatch(filename: str, detected_format: str, file_bytes: bytes) -> List[Dict[str, Any]]:
    """Check for discrepancy between declared file extension and underlying magic bytes."""
    findings = []
    ext = os.path.splitext(filename)[1].lower()
    header = file_bytes[:16]

    # Declared benign document, but actually executable binary
    if header.startswith(b"MZ") and ext not in {".exe", ".dll", ".sys", ".scr", ".com", ".cpl"}:
        findings.append({
            "rule_id": "RULE-EXT-MISMATCH-EXE",
            "title": "Severe Extension Mismatch: Windows PE Executable disguised as Document",
            "severity": "CRITICAL",
            "weight": 60,
            "explanation": "The file's magic bytes identify it as a compiled Windows PE binary (MZ header), but it was named with a benign extension.",
            "evidence": f"Extension is '{ext}', but file magic header is '4D 5A' (PE/MZ Executable).",
        })

    # Declared image, but actually ZIP or Executable
    if ext in {".jpg", ".jpeg", ".png", ".gif"} and (header.startswith(b"PK\x03\x04") or header.startswith(b"MZ")):
        findings.append({
            "rule_id": "RULE-EXT-MISMATCH-IMAGE",
            "title": "Severe Extension Mismatch: Archive or Binary disguised as Image",
            "severity": "HIGH",
            "weight": 45,
            "explanation": "File declared with an image extension but contains an archive or executable header, indicating steganography or payload concealment.",
            "evidence": f"Extension is '{ext}', but header identifies as {detected_format}.",
        })

    # Declared PDF, but does not start with %PDF
    if ext == ".pdf" and not header.startswith(b"%PDF"):
        # Could be RTF exploit or disguised script
        findings.append({
            "rule_id": "RULE-EXT-MISMATCH-PDF",
            "title": "File Format Mismatch: Declared PDF Lacks Standard PDF Header",
            "severity": "MEDIUM",
            "weight": 30,
            "explanation": "The file claims to be a PDF, but lacks standard '%PDF' magic header within its initial bytes.",
            "evidence": f"Initial bytes: {header[:8].hex()} instead of standard 25 50 44 46 (%PDF).",
        })

    return findings


def inspect_pdf_content(file_bytes: bytes) -> List[Dict[str, Any]]:
    """Perform bounded content inspection of PDF documents for automatic actions and JavaScript."""
    findings = []
    bounded = file_bytes[:MAX_BOUNDED_READ]

    # Search for active indicators in PDF structure
    pdf_indicators = [
        (b"/JavaScript", b"/JS", "RULE-PDF-JAVASCRIPT", "Embedded JavaScript Action in PDF", "HIGH", 40,
         "PDF contains embedded JavaScript streams or actions. Attackers frequently exploit PDF JavaScript engines for heap spraying or malicious payload execution."),
        (b"/OpenAction", b"/AA", "RULE-PDF-AUTOACTION", "Automatic Action (/OpenAction or /AA) Configured", "HIGH", 35,
         "Document is configured to execute an action immediately upon opening without requiring user interaction."),
        (b"/Launch", None, "RULE-PDF-LAUNCH", "PDF /Launch Action Present", "CRITICAL", 55,
         "The /Launch key instructs PDF reader software to execute an external application or command line on the host system."),
        (b"/EmbeddedFiles", None, "RULE-PDF-EMBEDDED", "PDF Contains Embedded Files Container", "MEDIUM", 25,
         "PDF includes an embedded files repository, which may conceal dropped scripts, archives, or secondary binaries."),
        (b"/URI", None, "RULE-PDF-EXTERNAL-URI", "PDF External URI Reference Detected", "LOW", 15,
         "Document contains external URI hyperlinks. While common in legitimate PDFs, these can be weaponized in phishing lures."),
    ]

    for primary, secondary, rule_id, title, sev, weight, explanation in pdf_indicators:
        matched = False
        evidence_snippet = ""
        if primary in bounded:
            matched = True
            evidence_snippet = f"Found marker: {primary.decode('ascii', errors='ignore')}"
        elif secondary and secondary in bounded:
            matched = True
            evidence_snippet = f"Found secondary marker: {secondary.decode('ascii', errors='ignore')}"

        if matched:
            findings.append({
                "rule_id": rule_id,
                "title": title,
                "severity": sev,
                "weight": weight,
                "explanation": explanation,
                "evidence": evidence_snippet,
            })

    return findings


def inspect_office_archive(file_bytes: bytes, filename: str) -> List[Dict[str, Any]]:
    """Safely inspect ZIP / Office OpenXML structure without writing or extracting files to disk."""
    findings = []
    
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            file_list = zf.infolist()
            
            # Check excessive entry count (potential zip bomb or obfuscation)
            if len(file_list) > 500:
                findings.append({
                    "rule_id": "RULE-ARCHIVE-EXCESSIVE-ENTRIES",
                    "title": "High Archive Entry Count (>500 entries)",
                    "severity": "MEDIUM",
                    "weight": 25,
                    "explanation": "Archive contains an unusually large quantity of files, which may indicate obfuscation or analysis evasion.",
                    "evidence": f"Total archive entries: {len(file_list)}",
                })

            total_uncompressed = 0
            has_macro = False
            suspicious_entries = []
            traversal_entries = []

            for entry in file_list:
                total_uncompressed += entry.file_size
                name_lower = entry.filename.lower()

                # Path traversal check
                if ".." in entry.filename or entry.filename.startswith("/") or entry.filename.startswith("\\"):
                    traversal_entries.append(entry.filename)

                # Macro indicators
                if "vbaproject.bin" in name_lower or "word/vba" in name_lower or "xl/vba" in name_lower:
                    has_macro = True

                # Dangerous executables or scripts bundled inside
                entry_ext = os.path.splitext(entry.filename)[1].lower()
                if entry_ext in DANGEROUS_EXTENSIONS:
                    suspicious_entries.append(entry.filename)

            # Check compression ratio bomb safety
            compressed_size = max(len(file_bytes), 1)
            ratio = total_uncompressed / compressed_size
            if ratio > 100 and total_uncompressed > 50 * 1024 * 1024:
                findings.append({
                    "rule_id": "RULE-ARCHIVE-DECOMPRESSION-BOMB",
                    "title": "Potential Decompression Bomb (High Ratio)",
                    "severity": "HIGH",
                    "weight": 50,
                    "explanation": "Compression ratio exceeds 100:1 with high uncompressed volume, typical of zip bombs engineered to exhaust analyzer memory.",
                    "evidence": f"Compression ratio: {ratio:.1f}:1 (Uncompressed: {total_uncompressed / 1024 / 1024:.1f} MB)",
                })

            if traversal_entries:
                findings.append({
                    "rule_id": "RULE-ARCHIVE-PATH-TRAVERSAL",
                    "title": "Directory Traversal Sequences in Archive Entries (Zip Slip)",
                    "severity": "CRITICAL",
                    "weight": 60,
                    "explanation": "Archive contains relative directory traversal paths ('../') that can overwrite arbitrary system files if extracted without validation.",
                    "evidence": f"Suspicious entry paths found: {', '.join(traversal_entries[:3])}",
                })

            if has_macro:
                findings.append({
                    "rule_id": "RULE-OFFICE-MACRO-CONTAINER",
                    "title": "VBA Macro Project Stream (vbaProject.bin) Present",
                    "severity": "HIGH",
                    "weight": 45,
                    "explanation": "Office container contains compiled VBA macro storage ('vbaProject.bin'), commonly used to execute downloader or stager routines.",
                    "evidence": "Archive contains embedded VBA binary: 'vbaProject.bin'",
                })

            if suspicious_entries:
                findings.append({
                    "rule_id": "RULE-ARCHIVE-EMBEDDED-EXEC",
                    "title": "Executable or Script Bundled Inside Archive",
                    "severity": "HIGH",
                    "weight": 40,
                    "explanation": "Archive contains nested executable or scripting binaries often leveraged in multi-stage email attachment attacks.",
                    "evidence": f"Bundled items: {', '.join(suspicious_entries[:4])}",
                })

    except zipfile.BadZipFile:
        # If declared as docx/xlsx/zip but not a valid zip
        ext = os.path.splitext(filename)[1].lower()
        if ext in {".docx", ".xlsx", ".pptx", ".zip"}:
            findings.append({
                "rule_id": "RULE-ARCHIVE-MALFORMED",
                "title": "Malformed Archive Structure / Parsing Failure",
                "severity": "MEDIUM",
                "weight": 25,
                "explanation": "File declares an archive-based format but failed standard ZIP header validation.",
                "evidence": f"BadZipFile parsing error on file: '{filename}'",
            })
    except Exception as e:
        findings.append({
            "rule_id": "RULE-ARCHIVE-INSPECTION-ERR",
            "title": "Archive Inspection Error",
            "severity": "LOW",
            "weight": 10,
            "explanation": f"Non-fatal error inspecting archive structure: {str(e)[:100]}",
            "evidence": str(e)[:100],
        })

    return findings


def inspect_strings_and_heuristics(file_bytes: bytes) -> List[Dict[str, Any]]:
    """Inspect bounded byte stream for suspicious command line signatures, encoded commands, and utility abuse."""
    findings = []
    bounded = file_bytes[:MAX_BOUNDED_READ]

    # Decode safely with replacement for regex analysis
    text_content = bounded.decode("latin-1", errors="ignore")

    for pattern, title, sev in SUSPICIOUS_STRING_PATTERNS:
        match = re.search(pattern, text_content)
        if match:
            snippet = match.group(0)[:120]
            weight_val = 45 if sev == "CRITICAL" else (35 if sev == "HIGH" else 20)
            findings.append({
                "rule_id": f"RULE-STRING-{sev}",
                "title": f"Suspicious Command Marker: {title}",
                "severity": sev,
                "weight": weight_val,
                "explanation": f"Observed string sequence matching known adversary tradecraft: {title}.",
                "evidence": f"Matched sequence: '{snippet}'",
            })

    # Embedded IPv4 URL / IP address heuristic
    raw_ip_urls = re.findall(r"https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?[^\s'\"<>]*", text_content)
    if raw_ip_urls:
        sample_ip_url = raw_ip_urls[0][:90]
        findings.append({
            "rule_id": "RULE-EMBEDDED-RAW-IP-URL",
            "title": "Direct IP-Based External URL Detected",
            "severity": "MEDIUM",
            "weight": 25,
            "explanation": "Attachment embeds direct IP address URLs rather than registered domain names, characteristic of uncategorized adversary C2 infrastructure.",
            "evidence": f"Found direct IP URL: {sample_ip_url}",
        })

    return findings


def analyze_file(filename: str, file_bytes: bytes, original_filename: Optional[str] = None) -> Dict[str, Any]:
    """Run full bounded static analysis pipeline on submitted attachment."""
    safe_name = sanitize_filename(original_filename or filename)
    file_size = len(file_bytes)
    ext = os.path.splitext(safe_name)[1].lower()

    limitations = [
        "Static inspection is bounded to the initial 2 MB of content to prevent denial-of-service.",
        "Archive inspection is performed strictly in-memory without host disk extraction or code execution.",
        "A Low risk score indicates no suspicious static signatures were matched within inspected boundaries; this does not certify the attachment as safe.",
        "Dynamic behavior (network calls, memory injection) requires correlation with sandbox reports."
    ]

    # 1. Size verification
    if file_size > MAX_FILE_SIZE:
        return {
            "error": f"File size ({file_size / 1024 / 1024:.2f} MB) exceeds maximum allowed limit of {MAX_FILE_SIZE / 1024 / 1024:.0f} MB.",
            "file_size": file_size,
        }

    # 2. SHA-256 calculation
    sha256_hash = compute_sha256(file_bytes)

    # 3. Magic signature detection
    sig_hex, detected_format = detect_magic_signature(file_bytes)

    # 4. Aggregated findings list
    findings: List[Dict[str, Any]] = []

    # Filename inspections
    findings.extend(inspect_filename(safe_name))

    # Extension mismatch checks
    findings.extend(check_extension_mismatch(safe_name, detected_format, file_bytes))

    # Format specific inspections
    if detected_format.startswith("Adobe Portable") or ext == ".pdf":
        findings.extend(inspect_pdf_content(file_bytes))

    if detected_format.startswith("ZIP") or ext in {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".zip"}:
        findings.extend(inspect_office_archive(file_bytes, safe_name))

    # Generic string & heuristic signatures
    findings.extend(inspect_strings_and_heuristics(file_bytes))

    # If unknown format with zero findings, clearly state limitations
    if detected_format.startswith("Unknown") and not findings:
        limitations.append("File format could not be verified against known magic byte signatures; manual SOC review recommended.")

    return {
        "filename": safe_name,
        "original_filename": original_filename or filename,
        "file_size": file_size,
        "file_extension": ext,
        "detected_format": detected_format,
        "magic_hex": sig_hex,
        "sha256": sha256_hash,
        "findings": findings,
        "limitations": limitations,
    }
