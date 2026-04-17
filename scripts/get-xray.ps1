# Downloads the latest Xray-core for Windows x64 -> src-tauri/binaries/
# Required for vless xhttp/splithttp transports (sing-box doesn't support them).
# Prints the SHA256 to paste into EXPECTED_XRAY_SHA256 in src-tauri/src/lib.rs.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\get-xray.ps1

$ErrorActionPreference = "Stop"

$repo   = "XTLS/Xray-core"
$outDir = Join-Path $PSScriptRoot "..\src-tauri\binaries"

Write-Host "Fetching latest Xray-core release info..."
$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
$version = $release.tag_name

# Xray publishes Xray-windows-64.zip (older) or Xray-core release assets
$assetName = "Xray-windows-64.zip"
$asset = $release.assets | Where-Object { $_.name -eq $assetName }
if (-not $asset) {
    Write-Error "Asset $assetName not found in release $version. Available assets: $($release.assets.name -join ', ')"
    exit 1
}

$zipPath = Join-Path $env:TEMP $assetName
Write-Host "Downloading $assetName ($([math]::Round($asset.size/1MB,1)) MB)..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

$extractDir = Join-Path $env:TEMP "xray-extract"
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractDir

$exePath = Get-ChildItem -Path $extractDir -Filter "xray.exe" -Recurse |
           Select-Object -First 1 -ExpandProperty FullName
if (-not $exePath) {
    Write-Error "xray.exe not found in archive"
    exit 1
}

$triple   = "x86_64-pc-windows-msvc"
$destName = "xray-$triple.exe"
$destPath = Join-Path $outDir $destName

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Copy-Item -Path $exePath -Destination $destPath -Force

$hash = Get-FileHash -Path $destPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
$hashLower = $hash.ToLower()

Remove-Item $zipPath -Force
Remove-Item $extractDir -Recurse -Force

Write-Host ""
Write-Host "Done: $destPath" -ForegroundColor Green
Write-Host "Xray version: $version"
Write-Host "SHA256: $hashLower" -ForegroundColor Yellow
Write-Host ""
Write-Host "=> Update src-tauri/src/lib.rs:" -ForegroundColor Cyan
Write-Host "   const EXPECTED_XRAY_SHA256: &str = `"$hashLower`";"
