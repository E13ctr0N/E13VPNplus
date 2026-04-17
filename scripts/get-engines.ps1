# Downloads all VPN engine binaries required by E13VPN:
#   - sing-box (primary, all transports except xhttp)
#   - xray-core (xhttp/splithttp transport support)
#   - tun2socks (TUN routing when engine=Xray)
#
# After completion, paste the printed SHA256 values into lib.rs:
#   EXPECTED_SINGBOX_SHA256, EXPECTED_XRAY_SHA256, EXPECTED_TUN2SOCKS_SHA256
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

Write-Host "=== tun2socks ==="
& (Join-Path $scripts "get-tun2socks.ps1")
Write-Host ""

Write-Host "All engines downloaded to src-tauri/binaries/" -ForegroundColor Green
Write-Host "Remember to update SHA256 constants in src-tauri/src/lib.rs" -ForegroundColor Yellow
