# abv0 installer for Windows (PowerShell 5.1+).
#
#   irm https://raw.githubusercontent.com/gugu8intel-i9/abv0/main/install.ps1 | iex
#
# Downloads over HTTPS only, verifies the published SHA-256, refuses empty or
# non-executable payloads, and publishes atomically.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo = 'gugu8intel-i9/abv0'
$Ref  = if ($env:ABV0_REF) { $env:ABV0_REF } else { 'main' }
$Base = "https://raw.githubusercontent.com/$Repo/$Ref"

$Root    = if ($env:ABV0_HOME) { $env:ABV0_HOME } else { Join-Path $env:USERPROFILE '.abv0' }
$BinDir  = Join-Path $Root 'bin'
$RegDir  = Join-Path $Root 'registry'

function Die($msg) { Write-Error "error: $msg"; exit 1 }

# Allow TLS 1.2 and 1.3. TLS 1.2 is not the default on older PowerShell hosts,
# and the Tls13 enum member is missing on runtimes that predate it, so fall
# back to Tls12 alone in that case.
if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
} else {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { $Target = 'abv0-windows-x86_64.exe' }
    'ARM64' { $Target = 'abv0-windows-aarch64.exe' }
    'x86'   { Die '32-bit Windows is not supported' }
    default { Die "unsupported architecture '$env:PROCESSOR_ARCHITECTURE'" }
}

Write-Host "installing abv0 ($Target)"

New-Item -ItemType Directory -Force -Path $BinDir, $RegDir | Out-Null

$Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("abv0-install-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $Tmp | Out-Null

try {
    $exePath = Join-Path $Tmp 'abv0.exe'

    Write-Host 'downloading binary'
    Invoke-WebRequest -Uri "$Base/release/$Target" -OutFile $exePath -UseBasicParsing

    if (-not (Test-Path $exePath) -or (Get-Item $exePath).Length -eq 0) {
        Die 'downloaded binary is empty'
    }

    # A PE image starts with "MZ". Anything else is an error page.
    $head = [System.IO.File]::ReadAllBytes($exePath)[0..1]
    if ($head[0] -ne 0x4D -or $head[1] -ne 0x5A) {
        Die 'downloaded file is not a Windows executable (the server may have returned an error page)'
    }

    Write-Host 'verifying checksum'
    $sumsPath = Join-Path $Tmp 'SHA256SUMS'
    Invoke-WebRequest -Uri "$Base/release/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing

    $expected = $null
    foreach ($line in Get-Content $sumsPath) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].Trim() -eq $Target) { $expected = $parts[0].Trim() }
    }
    if (-not $expected) { Die "no checksum published for $Target" }

    $actual = (Get-FileHash -Algorithm SHA256 -Path $exePath).Hash.ToLower()
    if ($actual -ne $expected.ToLower()) {
        Die "checksum mismatch`n  expected $expected`n  actual   $actual`nRefusing to install."
    }

    # Sanity check before publishing.
    & $exePath version | Out-Null
    if ($LASTEXITCODE -ne 0) { Die 'the downloaded binary did not run on this machine' }

    Move-Item -Force -Path $exePath -Destination (Join-Path $BinDir 'abv0.exe')

    # The index is installed only together with its detached signature. The
    # signature is not checked here: abv0 verifies it the first time it reads
    # the index. Without it, nothing is installed and abv0 fetches the index on
    # first run.
    Write-Host 'fetching registry index'
    try {
        $idx    = Join-Path $Tmp 'index.json'
        $idxSig = Join-Path $Tmp 'index.json.sig'
        Invoke-WebRequest -Uri "$Base/packages/index.json" -OutFile $idx -UseBasicParsing
        Invoke-WebRequest -Uri "$Base/packages/index.json.sig" -OutFile $idxSig -UseBasicParsing
        if ((Get-Item $idx).Length -eq 0 -or (Get-Item $idxSig).Length -eq 0) {
            throw 'registry download is empty'
        }
        # Signature first: a new index is never on disk without its signature.
        Move-Item -Force -Path $idxSig -Destination (Join-Path $RegDir 'index.json.sig')
        Move-Item -Force -Path $idx -Destination (Join-Path $RegDir 'index.json')
    } catch {
        Write-Host "warning: could not fetch the registry index and its signature; abv0 will fetch them on first run (or run 'abv0 update')"
    }
}
finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "abv0 installed to $BinDir\abv0.exe"
& (Join-Path $BinDir 'abv0.exe') version

# Persist PATH for future sessions (user scope, no admin rights needed).
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$BinDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$BinDir;$userPath", 'User')
    Write-Host "added $BinDir to your user PATH"
}
$env:Path = "$BinDir;$env:Path"

Write-Host ''
Write-Host 'try:'
Write-Host '    abv0 list'
Write-Host '    abv0 install ripgrep'
