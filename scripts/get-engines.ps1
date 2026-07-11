# Downloads all VPN engine binaries required by E13VPN:
#   - sing-box (primary for regular transports, TUN/router helper for Xray)
#   - xray-core (xhttp/splithttp transport support)
#
# After completion, paste the printed SHA256 values into lib.rs:
#   EXPECTED_SINGBOX_SHA256, EXPECTED_XRAY_SHA256
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\get-engines.ps1

$ErrorActionPreference = "Stop"
$scripts = $PSScriptRoot

Write-Host "=== sing-box ==="
& (Join-Path $scripts "get-singbox.ps1")
Write-Host ""

Write-Host "=== xray-core ==="
& (Join-Path $scripts "get-xray.ps1")
Write-Host ""

Write-Host "All engines downloaded to src-tauri/binaries/" -ForegroundColor Green
Write-Host "Remember to update SHA256 constants in src-tauri/src/lib.rs" -ForegroundColor Yellow
