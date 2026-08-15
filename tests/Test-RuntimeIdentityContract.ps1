#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$verifyPath = Join-Path $repo 'Verify-Release.ps1'
$launcherPath = Join-Path $repo 'GatewayLANLink.bat'
$manifestPath = Join-Path $repo 'MANIFEST.json'
$metadataPath = Join-Path $repo 'PACKAGE_METADATA.json'
$versionPath = Join-Path $repo 'VERSION.txt'
$corePath = Join-Path $repo 'LAN_Router_Comms.ps1'

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Invoke-ReleaseVerifier {
    param([Parameter(Mandatory=$true)][string]$Root)
    $path = Join-Path $Root 'Verify-Release.ps1'
    & powershell.exe -NoLogo -NoProfile -File $path -Quiet *> $null
    return [int]$LASTEXITCODE
}

function Get-TreeFingerprint {
    param([Parameter(Mandatory=$true)][string]$Root)
    $prefix = $Root.TrimEnd([char[]]@('\','/'))
    $lines = foreach ($file in @(Get-ChildItem -LiteralPath $Root -Recurse -File | Sort-Object FullName)) {
        $relative = $file.FullName.Substring($prefix.Length).TrimStart([char[]]@('\','/')).Replace('\','/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        '{0}|{1}|{2}' -f $relative, $file.Length, $hash
    }
    return ($lines -join "`n")
}

function Copy-RuntimePackage {
    param([Parameter(Mandatory=$true)][string]$Destination)
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($name in @('GatewayLANLink.bat','Verify-Release.ps1','LAN_Router_Comms.ps1','VERSION.txt','PACKAGE_METADATA.json','MANIFEST.json')) {
        Copy-Item -LiteralPath (Join-Path $repo $name) -Destination (Join-Path $Destination $name) -Force
    }
}

foreach ($path in @($verifyPath,$launcherPath,$manifestPath,$metadataPath,$versionPath,$corePath)) {
    Assert-True (Test-Path -LiteralPath $path -PathType Leaf) ("Required runtime identity file is missing: $path")
}

$launcher = Get-Content -LiteralPath $launcherPath -Raw
$verifyPosition = $launcher.IndexOf('Verify-Release.ps1', [StringComparison]::OrdinalIgnoreCase)
$corePosition = $launcher.LastIndexOf('LAN_Router_Comms.ps1', [StringComparison]::OrdinalIgnoreCase)
Assert-True ($verifyPosition -ge 0) 'The canonical launcher does not invoke Verify-Release.ps1.'
Assert-True ($corePosition -gt $verifyPosition) 'The source engine is referenced before the verifier in the canonical launcher.'
Assert-True ($launcher -match 'if errorlevel 1') 'The canonical launcher must stop after a verifier failure.'
Assert-True ($launcher -notmatch '(?i)ExecutionPolicy\s+Bypass') 'The canonical launcher must not bypass execution policy.'

$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
$version = @{}
foreach ($line in ((Get-Content -LiteralPath $versionPath -Raw) -split "`r?`n")) {
    if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) { continue }
    $separator = $line.IndexOf('=')
    if ($separator -gt 0) { $version[$line.Substring(0,$separator).Trim()] = $line.Substring($separator + 1).Trim() }
}
$core = Get-Content -LiteralPath $corePath -Raw
Assert-True ([string]$metadata.parameter_baseline -eq '2.17.9') 'PACKAGE_METADATA.json is not aligned to parameter baseline 2.17.9.'
Assert-True ([bool]$metadata.runtime_identity_gate.required) 'PACKAGE_METADATA.json does not require the runtime identity gate.'
$buildPattern = '\$script:BuildId\s*=\s*[''"]' + [regex]::Escape([string]$version.build_id) + '[''"]'
Assert-True ($core -match $buildPattern) 'The source engine build ID does not match VERSION.txt.'

$before = Get-TreeFingerprint -Root $repo
Assert-True ((Invoke-ReleaseVerifier -Root $repo) -eq 0) 'The clean source package failed runtime identity verification.'
$after = Get-TreeFingerprint -Root $repo
Assert-True ([string]::Equals($before, $after, [StringComparison]::Ordinal)) 'The read-only verifier modified the source tree.'

$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('gll-runtime-identity-' + [guid]::NewGuid().ToString('N'))
try {
    $tamperRoot = Join-Path $tempRoot 'tamper'
    Copy-RuntimePackage -Destination $tamperRoot
    Add-Content -LiteralPath (Join-Path $tamperRoot 'LAN_Router_Comms.ps1') -Value "`n# synthetic tamper" -Encoding UTF8
    Assert-True ((Invoke-ReleaseVerifier -Root $tamperRoot) -ne 0) 'The verifier accepted a modified source engine.'

    $escapeRoot = Join-Path $tempRoot 'escape'
    Copy-RuntimePackage -Destination $escapeRoot
    $escapeManifest = Get-Content -LiteralPath (Join-Path $escapeRoot 'MANIFEST.json') -Raw | ConvertFrom-Json
    $escapeManifest.files[0].path = '../escape.txt'
    $escapeManifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $escapeRoot 'MANIFEST.json') -Encoding UTF8
    Assert-True ((Invoke-ReleaseVerifier -Root $escapeRoot) -ne 0) 'The verifier accepted an escaping manifest path.'

    $duplicateRoot = Join-Path $tempRoot 'duplicate'
    Copy-RuntimePackage -Destination $duplicateRoot
    $duplicateManifest = Get-Content -LiteralPath (Join-Path $duplicateRoot 'MANIFEST.json') -Raw | ConvertFrom-Json
    $first = $duplicateManifest.files[0]
    $duplicateEntry = [pscustomobject]@{ path = [string]$first.path; hash_mode = [string]$first.hash_mode; size = [int64]$first.size; sha256 = [string]$first.sha256 }
    $duplicateManifest.files = @($duplicateManifest.files) + @($duplicateEntry)
    $duplicateManifest | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $duplicateRoot 'MANIFEST.json') -Encoding UTF8
    Assert-True ((Invoke-ReleaseVerifier -Root $duplicateRoot) -ne 0) 'The verifier accepted a duplicate manifest path.'
} finally {
    if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host 'PASS: Gateway LAN Link runtime identity gate accepts the exact package, writes nothing, and rejects tamper/path conflicts.' -ForegroundColor Green
$global:LASTEXITCODE = 0
exit 0
