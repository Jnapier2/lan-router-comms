#requires -Version 5.1
<#
Read-only Gateway LAN Link runtime identity and managed-file integrity gate.

Copyright © 2026 Gateway Information Group LLC. All rights reserved.
#>
[CmdletBinding()]
param(
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Root = [IO.Path]::GetFullPath((Split-Path -Parent $MyInvocation.MyCommand.Path))
$script:VersionPath = Join-Path $script:Root 'VERSION.txt'
$script:MetadataPath = Join-Path $script:Root 'PACKAGE_METADATA.json'
$script:ManifestPath = Join-Path $script:Root 'MANIFEST.json'
$script:RequiredManagedFiles = @(
    'GatewayLANLink.bat',
    'Verify-Release.ps1',
    'LAN_Router_Comms.ps1',
    'VERSION.txt',
    'PACKAGE_METADATA.json'
)

function Assert-Contract {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Get-RequiredProperty {
    param([Parameter(Mandatory=$true)]$Object, [Parameter(Mandatory=$true)][string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    Assert-Contract ($null -ne $property) ("Required JSON property is missing: $Name")
    return $property.Value
}

function Read-RegularTextFile {
    param([Parameter(Mandatory=$true)][string]$Path, [ValidateRange(1,4194304)][int]$MaxBytes = 1048576)
    Assert-Contract (Test-Path -LiteralPath $Path -PathType Leaf) ("Required file is missing: $Path")
    $item = Get-Item -LiteralPath $Path -Force
    Assert-Contract (-not $item.PSIsContainer) ("Expected a regular file: $Path")
    Assert-Contract (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) ("Linked or reparse-point files are not accepted: $Path")
    Assert-Contract ($item.Length -le $MaxBytes) ("File exceeds the verification byte limit: $Path")
    return [IO.File]::ReadAllText($item.FullName, [Text.Encoding]::UTF8)
}

function Read-BoundedJson {
    param([Parameter(Mandatory=$true)][string]$Path)
    $text = Read-RegularTextFile -Path $Path -MaxBytes 1048576
    Assert-Contract (-not [string]::IsNullOrWhiteSpace($text)) ("JSON file is empty: $Path")
    return ($text | ConvertFrom-Json)
}

function Read-VersionContract {
    param([Parameter(Mandatory=$true)][string]$Path)
    $text = Read-RegularTextFile -Path $Path -MaxBytes 65536
    $result = @{}
    foreach ($rawLine in ($text -split "`r?`n")) {
        $line = [string]$rawLine
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) { continue }
        $separator = $line.IndexOf('=')
        Assert-Contract ($separator -gt 0) ("Invalid VERSION.txt line: $line")
        $key = $line.Substring(0, $separator).Trim()
        $value = $line.Substring($separator + 1).Trim()
        Assert-Contract (-not [string]::IsNullOrWhiteSpace($key)) 'VERSION.txt contains an empty key.'
        Assert-Contract (-not $result.ContainsKey($key)) ("VERSION.txt contains a duplicate key: $key")
        $result[$key] = $value
    }
    foreach ($required in @('package_id','version','build_id','parameter_baseline','canonical_entrypoint','execution_namespace')) {
        Assert-Contract ($result.ContainsKey($required)) ("VERSION.txt is missing required key: $required")
        Assert-Contract (-not [string]::IsNullOrWhiteSpace([string]$result[$required])) ("VERSION.txt value is empty: $required")
    }
    return $result
}

function Resolve-ManagedFile {
    param([Parameter(Mandatory=$true)][string]$RelativePath)
    Assert-Contract (-not [string]::IsNullOrWhiteSpace($RelativePath)) 'Manifest path is empty.'
    Assert-Contract (-not [IO.Path]::IsPathRooted($RelativePath)) ("Manifest path must be relative: $RelativePath")
    $normalized = $RelativePath.Replace('\','/')
    Assert-Contract (-not $normalized.StartsWith('/')) ("Manifest path must not begin with a separator: $RelativePath")
    $segments = @($normalized.Split('/'))
    Assert-Contract ($segments.Count -gt 0) ("Manifest path has no segments: $RelativePath")
    foreach ($segment in $segments) {
        Assert-Contract (-not [string]::IsNullOrWhiteSpace($segment)) ("Manifest path contains an empty segment: $RelativePath")
        Assert-Contract ($segment -notin @('.','..')) ("Manifest path escapes or aliases the package root: $RelativePath")
        Assert-Contract ($segment.IndexOf(':') -lt 0) ("Manifest path contains an invalid colon: $RelativePath")
    }
    $nativeRelative = $normalized.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $full = [IO.Path]::GetFullPath((Join-Path $script:Root $nativeRelative))
    $rootPrefix = $script:Root.TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
    Assert-Contract ($full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) ("Manifest path escapes the package root: $RelativePath")
    return [pscustomobject]@{
        Relative = ($segments -join '/')
        Full = $full
    }
}

try {
    $version = Read-VersionContract -Path $script:VersionPath
    $metadata = Read-BoundedJson -Path $script:MetadataPath
    $manifest = Read-BoundedJson -Path $script:ManifestPath

    $metadataPackage = [string](Get-RequiredProperty -Object $metadata -Name 'package_id')
    $metadataVersion = [string](Get-RequiredProperty -Object $metadata -Name 'version')
    $metadataBuild = [string](Get-RequiredProperty -Object $metadata -Name 'build_id')
    $metadataBaseline = [string](Get-RequiredProperty -Object $metadata -Name 'parameter_baseline')
    $metadataEntrypoint = [string](Get-RequiredProperty -Object $metadata -Name 'canonical_entrypoint')
    $metadataNamespace = [string](Get-RequiredProperty -Object $metadata -Name 'execution_namespace')
    $identityGate = Get-RequiredProperty -Object $metadata -Name 'runtime_identity_gate'
    Assert-Contract ([bool](Get-RequiredProperty -Object $identityGate -Name 'required')) 'PACKAGE_METADATA.json must require the runtime identity gate.'

    $manifestPackage = [string](Get-RequiredProperty -Object $manifest -Name 'package_id')
    $manifestVersion = [string](Get-RequiredProperty -Object $manifest -Name 'version')
    $manifestBuild = [string](Get-RequiredProperty -Object $manifest -Name 'build_id')
    $manifestBaseline = [string](Get-RequiredProperty -Object $manifest -Name 'parameter_baseline')
    $entries = @(Get-RequiredProperty -Object $manifest -Name 'files')

    foreach ($comparison in @(
        @('package_id', [string]$version['package_id'], $metadataPackage, $manifestPackage),
        @('version', [string]$version['version'], $metadataVersion, $manifestVersion),
        @('build_id', [string]$version['build_id'], $metadataBuild, $manifestBuild),
        @('parameter_baseline', [string]$version['parameter_baseline'], $metadataBaseline, $manifestBaseline)
    )) {
        $name = [string]$comparison[0]
        Assert-Contract ([string]::Equals([string]$comparison[1], [string]$comparison[2], [StringComparison]::Ordinal)) ("VERSION.txt and PACKAGE_METADATA.json disagree on $name")
        Assert-Contract ([string]::Equals([string]$comparison[1], [string]$comparison[3], [StringComparison]::Ordinal)) ("VERSION.txt and MANIFEST.json disagree on $name")
    }
    Assert-Contract ([string]::Equals([string]$version['canonical_entrypoint'], $metadataEntrypoint, [StringComparison]::OrdinalIgnoreCase)) 'Canonical entrypoint identity does not agree.'
    Assert-Contract ([string]::Equals([string]$version['execution_namespace'], $metadataNamespace, [StringComparison]::Ordinal)) 'Execution namespace identity does not agree.'
    Assert-Contract ($entries.Count -gt 0) 'MANIFEST.json contains no managed files.'

    $seen = @{}
    $verified = 0
    [int64]$totalBytes = 0
    foreach ($entry in $entries) {
        $relative = [string](Get-RequiredProperty -Object $entry -Name 'path')
        $expectedHash = ([string](Get-RequiredProperty -Object $entry -Name 'sha256')).Trim().ToLowerInvariant()
        [int64]$expectedSize = [int64](Get-RequiredProperty -Object $entry -Name 'size')
        Assert-Contract ($expectedHash -match '^[0-9a-f]{64}$') ("Manifest SHA-256 is invalid: $relative")
        Assert-Contract ($expectedSize -ge 0) ("Manifest size is invalid: $relative")

        $resolved = Resolve-ManagedFile -RelativePath $relative
        $marker = $resolved.Relative.ToLowerInvariant()
        Assert-Contract (-not $seen.ContainsKey($marker)) ("Manifest contains a duplicate path: $($resolved.Relative)")
        $seen[$marker] = $true

        Assert-Contract (Test-Path -LiteralPath $resolved.Full -PathType Leaf) ("Managed file is missing: $($resolved.Relative)")
        $item = Get-Item -LiteralPath $resolved.Full -Force
        Assert-Contract (-not $item.PSIsContainer) ("Managed path is not a regular file: $($resolved.Relative)")
        Assert-Contract (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) ("Managed file is linked or a reparse point: $($resolved.Relative)")
        Assert-Contract ([int64]$item.Length -eq $expectedSize) ("Managed file size mismatch: $($resolved.Relative)")
        $actualHash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Contract ([string]::Equals($actualHash, $expectedHash, [StringComparison]::Ordinal)) ("Managed file SHA-256 mismatch: $($resolved.Relative)")
        $verified++
        $totalBytes += [int64]$item.Length
    }

    foreach ($requiredFile in $script:RequiredManagedFiles) {
        Assert-Contract ($seen.ContainsKey($requiredFile.ToLowerInvariant())) ("Manifest does not manage required runtime file: $requiredFile")
    }

    $coreText = Read-RegularTextFile -Path (Join-Path $script:Root 'LAN_Router_Comms.ps1') -MaxBytes 1048576
    $escapedVersion = [regex]::Escape([string]$version['version'])
    $escapedBuild = [regex]::Escape([string]$version['build_id'])
    Assert-Contract ($coreText -match ("\$script:Version\s*=\s*['\"]" + $escapedVersion + "['\"]")) 'Source engine version does not match the package contract.'
    Assert-Contract ($coreText -match ("\$script:BuildId\s*=\s*['\"]" + $escapedBuild + "['\"]")) 'Source engine build ID does not match the package contract.'

    if (-not $Quiet) {
        [ordered]@{
            status = 'PASS'
            package_id = [string]$version['package_id']
            version = [string]$version['version']
            build_id = [string]$version['build_id']
            parameter_baseline = [string]$version['parameter_baseline']
            files_verified = $verified
            managed_bytes = $totalBytes
            root = $script:Root
            verification_mode = 'read_only'
        } | ConvertTo-Json -Compress
    }
    exit 0
} catch {
    $message = [string]$_.Exception.Message
    Write-Host ("[FAIL] Gateway LAN Link release verification failed: {0}" -f $message) -ForegroundColor Red
    Write-Host 'Repair: replace the project with one complete checksum-verified package. Do not mix files from different builds.' -ForegroundColor Yellow
    exit 20
}
