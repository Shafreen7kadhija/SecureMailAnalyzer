# SecureMailAnalyzer — Windows Startup Script
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SecureMailAnalyzer — Email Threat Analysis Platform" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Check if frontend dist exists, if not build it
$DistPath = Join-Path $PSScriptRoot "frontend\dist\index.html"
if (-not (Test-Path $DistPath)) {
    Write-Host "[*] Building frontend production bundle..." -ForegroundColor Yellow
    Push-Location (Join-Path $PSScriptRoot "frontend")
    npm run build
    Pop-Location
}

Write-Host "[+] Starting Unified Server on http://127.0.0.1:5000" -ForegroundColor Green
Write-Host "[!] Press CTRL+C to stop the server" -ForegroundColor Gray
python (Join-Path $PSScriptRoot "backend\app.py")
