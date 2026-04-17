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

$triple  = "x86_64-pc-windows-msvc"
$destName = "sing-box-$triple.exe"
$destPath = Join-Path $outDir $destName

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Copy-Item -Path $exePath -Destination $destPath -Force

Remove-Item $zipPath -Force
Remove-Item $extractDir -Recurse -Force

Write-Host ""
Write-Host "Done: $destPath" -ForegroundColor Green
Write-Host "sing-box version: $version"
