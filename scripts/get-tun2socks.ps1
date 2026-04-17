# Downloads the latest tun2socks (xjasonlyu) for Windows x64 -> src-tauri/binaries/
# Required for TUN-mode when engine=Xray (Xray has no built-in TUN, uses wintun via tun2socks).
# Prints the SHA256 to paste into EXPECTED_TUN2SOCKS_SHA256 in src-tauri/src/lib.rs.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts\get-tun2socks.ps1

$ErrorActionPreference = "Stop"

$repo   = "xjasonlyu/tun2socks"
$outDir = Join-Path $PSScriptRoot "..\src-tauri\binaries"

Write-Host "Fetching latest tun2socks release info..."
$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
$version = $release.tag_name

# Release asset naming: tun2socks-windows-amd64.zip
$assetName = "tun2socks-windows-amd64.zip"
$asset = $release.assets | Where-Object { $_.name -eq $assetName }
if (-not $asset) {
    Write-Error "Asset $assetName not found in release $version. Available assets: $($release.assets.name -join ', ')"
    exit 1
}

$zipPath = Join-Path $env:TEMP $assetName
Write-Host "Downloading $assetName ($([math]::Round($asset.size/1MB,1)) MB)..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

$extractDir = Join-Path $env:TEMP "tun2socks-extract"
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractDir

# Archive may contain tun2socks-windows-amd64.exe or tun2socks.exe — accept both
$exePath = Get-ChildItem -Path $extractDir -Filter "tun2socks*.exe" -Recurse |
           Select-Object -First 1 -ExpandProperty FullName
if (-not $exePath) {
    Write-Error "tun2socks exe not found in archive"
    exit 1
}

$triple   = "x86_64-pc-windows-msvc"
$destName = "tun2socks-$triple.exe"
$destPath = Join-Path $outDir $destName

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Copy-Item -Path $exePath -Destination $destPath -Force

$hash = Get-FileHash -Path $destPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
$hashLower = $hash.ToLower()

Remove-Item $zipPath -Force
Remove-Item $extractDir -Recurse -Force

Write-Host ""
Write-Host "Done: $destPath" -ForegroundColor Green
Write-Host "tun2socks version: $version"
Write-Host "SHA256: $hashLower" -ForegroundColor Yellow
Write-Host ""
Write-Host "=> Update src-tauri/src/lib.rs:" -ForegroundColor Cyan
Write-Host "   const EXPECTED_TUN2SOCKS_SHA256: &str = `"$hashLower`";"
