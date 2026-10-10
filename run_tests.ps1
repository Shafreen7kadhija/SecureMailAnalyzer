# SecureMailAnalyzer — Windows Test Runner
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Running SecureMailAnalyzer Test Suite (23 Security Tests)" -ForegroundColor Cyan
Write-Host " Static Engine, Threat Story, Gmail API & Enforcement" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

python -m unittest discover tests -v
