# Downloads the latest sing-box for Windows x64 -> src-tauri/binaries/
# Usage: powershell -ExecutionPolicy Bypass -File scripts\get-singbox.ps1

$ErrorActionPreference = "Stop"

$repo   = "SagerNet/sing-box"
$outDir = Join-Path $PSScriptRoot "..\src-tauri\binaries"

Write-Host "Fetching latest release info..."
$release = Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest"
$version = $release.tag_name
$verNum  = $version.TrimStart('v')

$assetName = "sing-box-$verNum-windows-amd64.zip"
$asset = $release.assets | Where-Object { $_.name -eq $assetName }
if (-not $asset) {
    Write-Error "Asset $assetName not found in release $version"
    exit 1
}

$zipPath = Join-Path $env:TEMP $assetName
Write-Host "Downloading $assetName ($([math]::Round($asset.size/1MB,1)) MB)..."
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath -UseBasicParsing

$extractDir = Join-Path $env:TEMP "singbox-extract"
if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $extractDir

$exePath = Get-ChildItem -Path $extractDir -Filter "sing-box.exe" -Recurse |
           Select-Object -First 1 -ExpandProperty FullName
if (-not $exePath) {
    Write-Error "sing-box.exe not found in archive"
    exit 1
}
$cronetPath = Get-ChildItem -Path $extractDir -Filter "libcronet.dll" -Recurse |
              Select-Object -First 1 -ExpandProperty FullName
if (-not $cronetPath) {
    Write-Error "libcronet.dll not found in archive; NaiveProxy outbound requires it"
    exit 1
}

$triple  = "x86_64-pc-windows-msvc"
$destName = "sing-box-$triple.exe"
$destPath = Join-Path $outDir $destName
$cronetDest = Join-Path $outDir "libcronet.dll"

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Copy-Item -Path $exePath -Destination $destPath -Force
Copy-Item -Path $cronetPath -Destination $cronetDest -Force

$hash = Get-FileHash -Path $destPath -Algorithm SHA256 | Select-Object -ExpandProperty Hash
$hashLower = $hash.ToLower()
$cronetHash = Get-FileHash -Path $cronetDest -Algorithm SHA256 | Select-Object -ExpandProperty Hash
$cronetHashLower = $cronetHash.ToLower()

Remove-Item $zipPath -Force
Remove-Item $extractDir -Recurse -Force

Write-Host ""
Write-Host "Done: $destPath" -ForegroundColor Green
Write-Host "Done: $cronetDest" -ForegroundColor Green
Write-Host "sing-box version: $version"
Write-Host "SHA256: $hashLower" -ForegroundColor Yellow
Write-Host "libcronet SHA256: $cronetHashLower" -ForegroundColor Yellow
Write-Host ""
Write-Host "=> Update src-tauri/src/lib.rs:" -ForegroundColor Cyan
Write-Host "   const EXPECTED_SINGBOX_SHA256: &str = `"$hashLower`";"
Write-Host "   const EXPECTED_LIBCRONET_SHA256: &str = `"$cronetHashLower`";"
