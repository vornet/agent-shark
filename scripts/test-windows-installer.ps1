param([string]$Version = '1.0.0', [string]$Rid = 'win-x64')
$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../artifacts/installer-smoke'))
$profileHome = Join-Path $root 'profile with spaces'
$app = Join-Path $root 'installed'
New-Item -ItemType Directory -Force -Path (Join-Path $profileHome '.codex') | Out-Null
$config = Join-Path $profileHome '.codex/config.toml'
[System.IO.File]::WriteAllText($config, "# preserve`nmodel = 'custom'`n")
$installer = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot "../artifacts/release/AgentShark-$Version-$Rid-setup.exe"))
$process = Start-Process -FilePath $installer -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$app`"", "/PROFILEHOME=`"$profileHome`"") -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Installer failed: $($process.ExitCode)" }
$text = Get-Content -LiteralPath $config -Raw
if (-not $text.Contains('[mcp_servers.agent-shark]') -or -not $text.Contains("model = 'custom'")) { throw 'Client registration was not preserved/created correctly.' }
python scripts/smoke-release.py --payload $app --version $Version
if ($LASTEXITCODE -ne 0) { throw 'Installed MCP server failed smoke checks.' }
$uninstaller = Join-Path $app 'unins000.exe'
$process = Start-Process -FilePath $uninstaller -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART') -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Uninstaller failed: $($process.ExitCode)" }
$text = Get-Content -LiteralPath $config -Raw
if ($text.Contains('[mcp_servers.agent-shark]') -or -not $text.Contains("model = 'custom'")) { throw 'Uninstall did not safely remove managed configuration.' }
Write-Output 'Windows installer integration and uninstall checks passed using an isolated profile.'
