$ErrorActionPreference = "Stop"
$url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
$zip = "$PSScriptRoot\wintun.zip"
$out = "$PSScriptRoot\..\src-tauri\binaries"

Write-Host "Скачивание wintun..."
Invoke-WebRequest -Uri $url -OutFile $zip

Write-Host "Распаковка..."
Expand-Archive -Path $zip -DestinationPath "$PSScriptRoot\wintun_tmp" -Force
Copy-Item "$PSScriptRoot\wintun_tmp\wintun\bin\amd64\wintun.dll" "$out\wintun.dll" -Force

Remove-Item $zip -Force
Remove-Item "$PSScriptRoot\wintun_tmp" -Recurse -Force
Write-Host "wintun.dll скопирован в $out"
