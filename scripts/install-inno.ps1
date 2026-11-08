$ErrorActionPreference = 'Stop'
$destination = Join-Path $PSScriptRoot '../artifacts/build-tools'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$url = 'https://github.com/jrsoftware/issrc/releases/download/is-6_7_4/innosetup-6.7.4.exe'
$expectedDigest = 'sha256:a549929319f9120716677c685535ca4671e4b937b5fdc87e2585f32d8eb30e8c'
$installer = Join-Path $destination 'innosetup-6.7.4.exe'
Invoke-WebRequest -Uri $url -OutFile $installer
$actual = 'sha256:' + (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expectedDigest) { throw 'Inno Setup checksum mismatch.' }
$compilerDirectory = Join-Path $destination 'inno'
$process = Start-Process -FilePath $installer -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', "/DIR=`"$compilerDirectory`"") -WindowStyle Hidden -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Inno Setup bootstrap failed: $($process.ExitCode)" }
$compiler = Join-Path $compilerDirectory 'ISCC.exe'
if (-not (Test-Path -LiteralPath $compiler)) { throw 'Installer compiler not found.' }
if ($env:GITHUB_ENV) { "ISCC=$compiler" | Out-File -FilePath $env:GITHUB_ENV -Encoding utf8 -Append }
Write-Output $compiler
