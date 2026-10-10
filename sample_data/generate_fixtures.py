import os
import zipfile

sample_dir = os.path.dirname(os.path.abspath(__file__))

# 1. Suspicious double extension script (harmless batch script)
double_ext_path = os.path.join(sample_dir, "suspicious_invoice_double_ext.pdf.bat")
with open(double_ext_path, "w", encoding="utf-8") as f:
    f.write(
        "@echo off\n"
        "rem SAFE SYNTHETIC DEMONSTRATION FIXTURE - NOT A REAL EXPLOIT\n"
        "echo [SecureMailAnalyzer Synthetic Test] Harmless double-extension demonstration.\n"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Write-Host 'Simulated powershell invocation check'\n"
    )

# 2. Suspicious PDF with /OpenAction and /JavaScript
pdf_path = os.path.join(sample_dir, "suspicious_js_sample.pdf")
pdf_content = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('Safe demonstration of embedded JavaScript marker');) >>\nendobj\n"
    b"5 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 72 712 Td (Harmless PDF Content) Tj ET\nendstream\nendobj\n"
    b"xref\n0 6\n0000000000 65535 f \n0000000009 00000 n \n0000000074 00000 n \n0000000133 00000 n \n0000000216 00000 n \n0000000329 00000 n \n"
    b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n424\n%%EOF\n"
)
with open(pdf_path, "wb") as f:
    f.write(pdf_content)

# 3. Macro-enabled Office file structure (safe synthetic zip with vbaProject.bin dummy marker)
docm_path = os.path.join(sample_dir, "suspicious_macro_sample.docm")
with zipfile.ZipFile(docm_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    zf.writestr("[Content_Types].xml", '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
    zf.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>')
    zf.writestr("word/document.xml", '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Safe Synthetic Macro Demonstration Document</w:t></w:r></w:p></w:body></w:document>')
    # Harmless dummy vbaProject.bin containing benign text bytes
    zf.writestr("word/vbaProject.bin", b"VBA_PROJECT_SYNTHETIC_SAFE_TEST_BYTES_AutoOpen_Sub_Execute_Macro")

print("Generated sample fixtures successfully in:", sample_dir)
