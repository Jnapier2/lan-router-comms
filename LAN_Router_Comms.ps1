#requires -version 5.1
<#
LAN Router Comms v2.3.0 - Adaptive Transport Guard
Prime directive: deliver authenticated text and files between paired Windows PCs
on the same private router network, without cloud services, remote command execution,
hidden persistence, or firewall bypasses.

Public portfolio edition. Runtime state and support exports remain local and are
excluded from source control.
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu','Receiver','StartupTest','Health','RetryQueue','SupportExport','FirewallAdd','FirewallRemove')]
    [string]$Mode = 'Menu',
    [ValidateRange(1,65535)]
    [int]$Port = 57222
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security -ErrorAction Stop

$script:AppName = 'LAN Router Comms'
$script:Version = '2.3.0'
$script:ProtocolVersion = 2
$script:TlsProtocols = [Security.Authentication.SslProtocols]::None
$script:MinimumTlsProtocolValue = 3072 # TLS 1.2; TLS 1.3 is 12288 when exposed by the runtime
$script:Capabilities = @('text-v2','file-resume-v2','delivery-receipt-v2','os-tls-floor-v1','tcp-keepalive-v1','disk-admission-v1','retry-jitter-v1','session-quota-v1','startup-due-message-retry-v1')
$script:ScriptPath = [IO.Path]::GetFullPath($MyInvocation.MyCommand.Path)
$script:Root = [IO.Path]::GetFullPath((Split-Path -Parent $script:ScriptPath))
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:MaxFrameBytes = 2MB
$script:MaxTransferBytes = 10GB
$script:Entropy = [Text.Encoding]::UTF8.GetBytes('LAN-Link-v2|DPAPI|2026-07')
$script:RunId = [guid]::NewGuid().ToString('D')
$script:RunStartedUtc = [DateTime]::UtcNow
$script:RunStopwatch = [Diagnostics.Stopwatch]::StartNew()
$script:LastConfigUnknownKeys = @()
$script:DefaultMaxLogBytes = 10MB

$script:Paths = [ordered]@{
    Config          = Join-Path $script:Root 'config'
    State           = Join-Path $script:Root 'state'
    Logs            = Join-Path $script:Root 'logs'
    Temp            = Join-Path $script:Root 'temp'
    Exports         = Join-Path $script:Root 'exports'
    Diagnostics     = Join-Path $script:Root 'diag'
    Inbox           = Join-Path $script:Root 'inbox'
    InboxMessages   = Join-Path $script:Root 'inbox\messages'
    InboxFiles      = Join-Path $script:Root 'inbox\files'
    Identity        = Join-Path $script:Root 'state\identity'
    Peers           = Join-Path $script:Root 'state\peers'
    Invites         = Join-Path $script:Root 'state\invites'
    OutboxMessages  = Join-Path $script:Root 'state\outbox\messages'
    OutboxFiles     = Join-Path $script:Root 'state\outbox\files'
    Sent            = Join-Path $script:Root 'state\sent'
    DedupeMessages  = Join-Path $script:Root 'state\dedupe\messages'
    Replay          = Join-Path $script:Root 'state\replay'
    Incoming        = Join-Path $script:Root 'state\incoming-files'
    IncomingData    = Join-Path $script:Root 'state\incoming-files\data'
    Quarantine      = Join-Path $script:Root 'state\quarantine'
}


function Initialize-AppFolders {
    foreach ($path in $script:Paths.Values) {
        if (-not (Test-Path -LiteralPath $path)) {
            [void](New-Item -ItemType Directory -Path $path -Force)
        }
    }
}

function Get-UtcIso {
    return [DateTime]::UtcNow.ToString('o')
}



function Get-ActiveLogPath {
    $base = 'LAN_Router_Comms_{0}' -f [DateTime]::UtcNow.ToString('yyyyMMdd')
    $dayFiles = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt 20; $i++) {
        $suffix = if ($i -eq 0) { '' } else { '-{0:D2}' -f ($i + 1) }
        $candidate = Join-Path $script:Paths.Logs ($base + $suffix + '.log')
        if (-not (Test-Path -LiteralPath $candidate)) { return $candidate }
        try {
            $item = Get-Item -LiteralPath $candidate
            [void]$dayFiles.Add($item)
            if ($item.Length -lt $script:DefaultMaxLogBytes) { return $candidate }
        } catch { return $candidate }
    }
    # Hard bound: if all 20 daily segments are full, recycle the oldest segment
    # rather than creating an unbounded overflow file.
    $oldest = @($dayFiles.ToArray() | Sort-Object LastWriteTimeUtc | Select-Object -First 1)
    if ($oldest.Count) {
        try { Remove-Item -LiteralPath $oldest[0].FullName -Force -ErrorAction Stop; return $oldest[0].FullName } catch { }
    }
    throw 'The bounded log set is full and the oldest segment could not be recycled.'
}

function Write-AppLog {
    param(
        [ValidateSet('DEBUG','INFO','WARN','ERROR')][string]$Level,
        [string]$Message
    )
    try {
        $safe = [string]$Message
        $safe = $safe -replace '(?i)(invite_secret|shared_secret|password|secret_protected|text_protected)\s*[:=]\s*[^\s,;]+', '$1=[REDACTED]'
        $line = "{0}`trun={1}`telapsed_ms={2}`t{3}`t{4}" -f (Get-UtcIso), $script:RunId, $script:RunStopwatch.ElapsedMilliseconds, $Level, $safe
        [IO.File]::AppendAllText((Get-ActiveLogPath), $line + [Environment]::NewLine, $script:Utf8NoBom)
    } catch {
        # Logging must never break communications.
    }
}

function Write-Info([string]$Message) {
    Write-Host ('[+] ' + $Message)
    Write-AppLog -Level INFO -Message $Message
}
function Write-Warn([string]$Message) {
    Write-Host ('[!] ' + $Message) -ForegroundColor Yellow
    Write-AppLog -Level WARN -Message $Message
}
function Write-Fail([string]$Message) {
    Write-Host ('[X] ' + $Message) -ForegroundColor Red
    Write-AppLog -Level ERROR -Message $Message
}

function ConvertTo-CompactJson {
    param([Parameter(Mandatory=$true)]$InputObject, [int]$Depth = 12)
    return ($InputObject | ConvertTo-Json -Depth $Depth -Compress)
}

function Write-DurableBytes {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][byte[]]$Bytes
    )
    $full = [IO.Path]::GetFullPath($Path)
    $dir = Split-Path -Parent $full
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $tmp = Join-Path $dir ('.' + [IO.Path]::GetFileName($full) + '.tmp-' + [guid]::NewGuid().ToString('N'))
    try {
        $fs = [IO.FileStream]::new(
            $tmp,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write,
            [IO.FileShare]::None,
            65536,
            [IO.FileOptions]::WriteThrough
        )
        try {
            $fs.Write($Bytes, 0, $Bytes.Length)
            $fs.Flush($true)
        } finally {
            $fs.Dispose()
        }
        if (Test-Path -LiteralPath $full) {
            try {
                [IO.File]::Replace($tmp, $full, $null, $true)
            } catch {
                Move-Item -LiteralPath $tmp -Destination $full -Force
            }
        } else {
            [IO.File]::Move($tmp, $full)
        }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Write-DurableText {
    param([string]$Path, [string]$Text)
    Write-DurableBytes -Path $Path -Bytes $script:Utf8NoBom.GetBytes([string]$Text)
}

function Write-JsonFile {
    param([string]$Path, [Parameter(Mandatory=$true)]$Object)
    Write-DurableText -Path $Path -Text (ConvertTo-CompactJson -InputObject $Object -Depth 16)
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    if ([string]::IsNullOrWhiteSpace($text)) { throw "JSON file is empty: $Path" }
    return ($text | ConvertFrom-Json)
}

function New-RandomBytes {
    param([ValidateRange(1,4096)][int]$Count)
    $bytes = New-Object byte[] $Count
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ,$bytes
}

function Get-Sha256HexFromBytes {
    param([Parameter(Mandatory=$true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Get-Sha256HexFromFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = $sha.ComputeHash($stream) } finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
    return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Protect-BytesToBase64 {
    param([Parameter(Mandatory=$true)][byte[]]$Bytes)
    $protected = [Security.Cryptography.ProtectedData]::Protect(
        $Bytes,
        $script:Entropy,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return [Convert]::ToBase64String($protected)
}

function Unprotect-Base64ToBytes {
    param([Parameter(Mandatory=$true)][string]$ProtectedBase64)
    $protected = [Convert]::FromBase64String($ProtectedBase64)
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $protected,
        $script:Entropy,
        [Security.Cryptography.DataProtectionScope]::CurrentUser
    )
    return ,$plain
}

function Protect-TextToBase64 {
    param([Parameter(Mandatory=$true)][string]$Text)
    return Protect-BytesToBase64 -Bytes $script:Utf8NoBom.GetBytes($Text)
}

function Unprotect-Base64ToText {
    param([Parameter(Mandatory=$true)][string]$ProtectedBase64)
    return [Text.Encoding]::UTF8.GetString((Unprotect-Base64ToBytes -ProtectedBase64 $ProtectedBase64))
}

function Test-FixedTimeEqual {
    param([byte[]]$A, [byte[]]$B)
    if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
    [int]$diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) { $diff = $diff -bor ($A[$i] -bxor $B[$i]) }
    return ($diff -eq 0)
}


function Test-AcceptableTlsProtocol {
    param([Parameter(Mandatory=$true)]$Protocol)
    [int]$value = [int]$Protocol
    return ($value -eq $script:MinimumTlsProtocolValue -or $value -eq 12288)
}

function Get-TlsProtocolLabel {
    param([Parameter(Mandatory=$true)]$Protocol)
    switch ([int]$Protocol) {
        3072  { return 'TLS 1.2' }
        12288 { return 'TLS 1.3' }
        default { return ([string]$Protocol) }
    }
}

function Set-TcpKeepAlive {
    param(
        [Parameter(Mandatory=$true)][Net.Sockets.TcpClient]$TcpClient,
        [Parameter(Mandatory=$true)]$Config
    )
    try {
        $TcpClient.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::Socket,[Net.Sockets.SocketOptionName]::KeepAlive,$true)
        $values = New-Object byte[] 12
        ([BitConverter]::GetBytes([uint32]1)).CopyTo($values,0)
        ([BitConverter]::GetBytes([uint32][int]$Config.tcp_keepalive_time_ms)).CopyTo($values,4)
        ([BitConverter]::GetBytes([uint32][int]$Config.tcp_keepalive_interval_ms)).CopyTo($values,8)
        [void]$TcpClient.Client.IOControl([Net.Sockets.IOControlCode]::KeepAliveValues,$values,$null)
        return $true
    } catch {
        Write-AppLog -Level WARN -Message ('TCP keepalive configuration was unavailable; I/O timeouts remain active. ' + $_.Exception.Message)
        return $false
    }
}

function Get-FreeSpaceInfo {
    param([Parameter(Mandatory=$true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) { throw "Unable to determine the volume for $full." }
    $drive = [IO.DriveInfo]::new($root)
    if (-not $drive.IsReady) { throw "The destination volume is not ready: $root" }
    return [pscustomobject]@{ root=$root; available_bytes=[long]$drive.AvailableFreeSpace; total_bytes=[long]$drive.TotalSize }
}

function Assert-IncomingCapacity {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [ValidateRange(0,10737418240)][long]$AdditionalBytes,
        [Parameter(Mandatory=$true)]$Config
    )
    $space = Get-FreeSpaceInfo -Path $Path
    [long]$reserve = [long]$Config.min_free_space_mb * 1MB
    [long]$required = $AdditionalBytes + $reserve
    if ([long]$space.available_bytes -lt $required) {
        throw ('Insufficient destination free space. Required including reserve: {0:N1} MiB; available: {1:N1} MiB.' -f ($required/1MB),([long]$space.available_bytes/1MB))
    }
    return $space
}

function Get-RetryDelaySeconds {
    param(
        [ValidateRange(0,1000000)][int]$Attempts,
        [Parameter(Mandatory=$true)]$Config
    )
    [int]$baseDelay = [int][Math]::Min(900,[Math]::Pow(2,[Math]::Min(9,$Attempts))*5)
    [int]$percent = [int]$Config.retry_jitter_percent
    if ($percent -le 0 -or $baseDelay -ge 900) { return $baseDelay }
    [int]$maxJitter = [int][Math]::Floor(($baseDelay * $percent) / 100.0)
    if ($maxJitter -lt 1) { return $baseDelay }
    $randomBytes = New-RandomBytes 4
    [uint32]$randomValue = [BitConverter]::ToUInt32($randomBytes,0)
    [int]$jitter = [int]($randomValue % [uint32]($maxJitter + 1))
    return [int][Math]::Min(900,($baseDelay + $jitter))
}


function Get-ProjectMutexName {
    param([Parameter(Mandatory=$true)][string]$Purpose)
    $safePurpose = ($Purpose -replace '[^A-Za-z0-9_.-]','_')
    if ($safePurpose.Length -gt 48) { $safePurpose = $safePurpose.Substring(0,48) }
    $seed = $script:Utf8NoBom.GetBytes(($script:Root.ToLowerInvariant() + '|' + $Purpose.ToLowerInvariant()))
    $token = (Get-Sha256HexFromBytes $seed).Substring(0,24)
    # PowerShell does not use C-style backslash escaping. This must contain one namespace separator.
    return ('Local\LANRouterComms_' + $safePurpose + '_' + $token)
}

function Enter-ProjectMutex {
    param(
        [Parameter(Mandatory=$true)][string]$Purpose,
        [ValidateRange(0,300000)][int]$TimeoutMs = 15000
    )
    $mutex = [Threading.Mutex]::new($false,(Get-ProjectMutexName $Purpose))
    $acquired = $false
    try { $acquired = $mutex.WaitOne($TimeoutMs,$false) }
    catch [Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) {
        $mutex.Dispose()
        throw "Timed out waiting for the project operation lock: $Purpose"
    }
    return $mutex
}

function Exit-ProjectMutex {
    param($Mutex)
    if ($null -eq $Mutex) { return }
    try { $Mutex.ReleaseMutex() } catch { }
    try { $Mutex.Dispose() } catch { }
}


function Get-DefaultConfig {
    return [ordered]@{
        schema                    = 'lanlink-config-v2.2'
        listen_port               = 57222
        preferred_ip              = ''
        max_message_bytes         = 65536
        file_chunk_bytes          = 196608
        connect_timeout_ms        = 5000
        io_timeout_ms             = 30000
        tcp_keepalive_time_ms     = 15000
        tcp_keepalive_interval_ms = 5000
        max_session_seconds       = 3600
        max_session_requests      = 20000
        min_free_space_mb         = 1024
        retry_jitter_percent      = 25
        max_clock_skew_seconds    = 600
        sent_receipt_days         = 30
        replay_retention_days     = 7
        dedupe_retention_days     = 90
        invite_retention_days     = 2
        log_retention_days        = 14
        max_log_files             = 20
        max_pending_messages      = 500
        max_pending_files         = 100
        max_diag_inventory_files  = 5000
        max_diag_seconds          = 10
    }
}


function ConvertTo-UtcDateTime {
    param([Parameter(Mandatory=$true)][string]$Value)
    $dt = [DateTime]::MinValue
    if (-not [DateTime]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) {
        throw "Timestamp is invalid: $Value"
    }
    return $dt.ToUniversalTime()
}

function Normalize-AppConfig {
    param([Parameter(Mandatory=$true)]$Config)
    $ranges = [ordered]@{
        listen_port              = @(1,65535)
        max_message_bytes        = @(256,1048576)
        file_chunk_bytes         = @(16384,524288)
        connect_timeout_ms       = @(1000,60000)
        io_timeout_ms             = @(5000,300000)
        tcp_keepalive_time_ms     = @(5000,300000)
        tcp_keepalive_interval_ms = @(1000,60000)
        max_session_seconds       = @(60,86400)
        max_session_requests      = @(10,100000)
        min_free_space_mb         = @(0,1048576)
        retry_jitter_percent      = @(0,100)
        max_clock_skew_seconds    = @(30,3600)
        sent_receipt_days        = @(1,3650)
        replay_retention_days    = @(1,365)
        dedupe_retention_days    = @(7,3650)
        invite_retention_days    = @(1,30)
        log_retention_days       = @(1,365)
        max_log_files            = @(2,200)
        max_pending_messages     = @(1,10000)
        max_pending_files        = @(1,1000)
        max_diag_inventory_files = @(100,100000)
        max_diag_seconds         = @(2,120)
    }
    foreach ($name in $ranges.Keys) {
        [int]$value = 0
        if (-not [int]::TryParse([string]$Config[$name],[ref]$value) -or $value -lt $ranges[$name][0] -or $value -gt $ranges[$name][1]) {
            throw "Config setting '$name' is outside the supported range $($ranges[$name][0])..$($ranges[$name][1])."
        }
        $Config[$name] = $value
    }
    $preferred = [string]$Config['preferred_ip']
    if ($preferred -and -not (Test-PrivateIPv4 $preferred)) { throw 'Config setting preferred_ip must be blank or an RFC1918 private IPv4 address.' }
    $Config['schema'] = 'lanlink-config-v2.2'
    return $Config
}

function Get-ConfigAudit {
    $defaults = Get-DefaultConfig
    $path = Get-ConfigPath
    if (-not (Test-Path -LiteralPath $path)) { return [ordered]@{ schema='missing'; unknown_keys=@(); missing_keys=@($defaults.Keys); status='WARN' } }
    try {
        $raw = Read-JsonFile $path
        $names = @($raw.PSObject.Properties.Name)
        $unknown = @($names | Where-Object { $_ -notin @($defaults.Keys) } | Sort-Object -Unique)
        $missing = @($defaults.Keys | Where-Object { $_ -notin $names })
        $status = if ($unknown.Count -or $missing.Count -or [string]$raw.schema -ne 'lanlink-config-v2.2') { 'WARN' } else { 'PASS' }
        return [ordered]@{ schema=[string]$raw.schema; unknown_keys=$unknown; missing_keys=$missing; status=$status }
    } catch { return [ordered]@{ schema='unreadable'; unknown_keys=@(); missing_keys=@(); status='FAIL'; error=$_.Exception.Message } }
}

function Get-ConfigPath { return (Join-Path $script:Paths.Config 'settings.json') }


function Get-AppConfig {
    $path = Get-ConfigPath
    $defaults = Get-DefaultConfig
    $mutex = Enter-ProjectMutex -Purpose 'ConfigState' -TimeoutMs 15000
    try {
        if (-not (Test-Path -LiteralPath $path)) { Write-JsonFile -Path $path -Object $defaults }
        try {
            $raw = Read-JsonFile -Path $path
        } catch {
            $bad = Join-Path $script:Paths.Quarantine ('settings.unreadable-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.json')
            if (Test-Path -LiteralPath $path) { Move-Item -LiteralPath $path -Destination $bad -Force }
            $raw = [pscustomobject]$defaults
            Write-JsonFile -Path $path -Object $raw
            Write-Warn "An unreadable settings file was quarantined as $(Split-Path -Leaf $bad); safe defaults were restored."
        }
        try {
            $names = @($raw.PSObject.Properties.Name)
            $cfg = [ordered]@{}
            $changed = $false
            foreach ($key in $defaults.Keys) {
                if ($key -in $names) { $cfg[$key] = $raw.$key } else { $cfg[$key] = $defaults[$key]; $changed = $true }
            }
            $unknown = @($names | Where-Object { $_ -notin @($defaults.Keys) } | Sort-Object -Unique)
            foreach ($key in $unknown) { $cfg[$key] = $raw.$key }
            $script:LastConfigUnknownKeys = $unknown
            if ([string]$raw.schema -ne 'lanlink-config-v2.2') { $changed = $true }
            $cfg = Normalize-AppConfig $cfg
        } catch {
            $reason = $_.Exception.Message
            $bad = Join-Path $script:Paths.Quarantine ('settings.invalid-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.json')
            if (Test-Path -LiteralPath $path) { Move-Item -LiteralPath $path -Destination $bad -Force }
            $cfg = Get-DefaultConfig
            $unknown = @()
            $script:LastConfigUnknownKeys = @()
            Write-JsonFile -Path $path -Object $cfg
            Write-Warn "An invalid settings file was quarantined as $(Split-Path -Leaf $bad); safe defaults were restored. Reason: $reason"
            return [pscustomobject]$cfg
        }
        if ($changed) {
            $backup = Join-Path $script:Paths.Config ('settings.pre-v2.2-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmssfff') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.json')
            if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination $backup -Force }
            Write-JsonFile -Path $path -Object $cfg
            Write-Info 'Config was migrated to schema lanlink-config-v2.2; the previous file was preserved.'
        }
        if ($unknown.Count) { Write-Warn ('Unknown config key(s) were preserved but are not used: ' + ($unknown -join ', ')) }
        return [pscustomobject]$cfg
    } finally { Exit-ProjectMutex $mutex }
}

function Save-AppConfig($Config) {
    $mutex = Enter-ProjectMutex -Purpose 'ConfigState' -TimeoutMs 15000
    try {
        $map = [ordered]@{}
        foreach ($p in $Config.PSObject.Properties) { $map[$p.Name] = $p.Value }
        $map = Normalize-AppConfig $map
        Write-JsonFile -Path (Get-ConfigPath) -Object $map
    } finally { Exit-ProjectMutex $mutex }
}


function Remove-OldFilesBounded {
    param([string]$Path,[string]$Filter='*',[int]$RetentionDays=30,[int]$KeepNewest=100,[switch]$Recurse)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $cutoff = [DateTime]::UtcNow.AddDays(-1 * $RetentionDays)
    $items = @(Get-ChildItem -LiteralPath $Path -Filter $Filter -File -Recurse:$Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending)
    [int]$removed = 0
    for ($i=0; $i -lt $items.Count; $i++) {
        if ($i -ge $KeepNewest -or $items[$i].LastWriteTimeUtc -lt $cutoff) {
            try { Remove-Item -LiteralPath $items[$i].FullName -Force -ErrorAction Stop; $removed++ } catch { }
        }
    }
    return $removed
}


function Invoke-Housekeeping {
    try {
        $cfg = Get-AppConfig
        $removed = 0
        $removed += Remove-OldFilesBounded -Path $script:Paths.Logs -Filter '*.log' -RetentionDays ([int]$cfg.log_retention_days) -KeepNewest ([int]$cfg.max_log_files)
        $removed += Remove-OldFilesBounded -Path $script:Paths.Sent -Filter '*.json' -RetentionDays ([int]$cfg.sent_receipt_days) -KeepNewest 5000
        $removed += Remove-OldFilesBounded -Path $script:Paths.Replay -Filter '*.seen' -RetentionDays ([int]$cfg.replay_retention_days) -KeepNewest 20000 -Recurse
        $removed += Remove-OldFilesBounded -Path $script:Paths.DedupeMessages -Filter '*.json' -RetentionDays ([int]$cfg.dedupe_retention_days) -KeepNewest 50000 -Recurse
        $removed += Remove-OldFilesBounded -Path $script:Paths.Temp -Filter '*' -RetentionDays 2 -KeepNewest 200
        foreach ($f in @(Get-ChildItem -LiteralPath $script:Paths.Invites -Filter '*.json' -File -ErrorAction SilentlyContinue)) {
            try {
                $state = Read-JsonFile $f.FullName
                $expiry = ConvertTo-UtcDateTime ([string]$state.expires_utc)
                if ([DateTime]::UtcNow -gt $expiry.AddDays([int]$cfg.invite_retention_days)) {
                    if ($state.export_rel_path) {
                        try {
                            $exportPath = Resolve-ProjectRelativePath ([string]$state.export_rel_path)
                            Remove-Item -LiteralPath $exportPath -Force -ErrorAction SilentlyContinue
                        } catch { }
                    }
                    Remove-Item -LiteralPath $f.FullName -Force
                    $removed++
                }
            } catch { }
        }
        if ($removed) { Write-AppLog -Level INFO -Message "Housekeeping removed $removed expired/bounded file(s)." }
    } catch { Write-AppLog -Level WARN -Message ('Housekeeping skipped: ' + $_.Exception.Message) }
}

function Get-ProjectRelativePath {
    param([Parameter(Mandatory=$true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $rootPrefix = $script:Root.TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)) + [IO.Path]::DirectorySeparatorChar
    if ($full.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) { return $full.Substring($rootPrefix.Length) }
    return ''
}

function Resolve-ProjectRelativePath {
    param([Parameter(Mandatory=$true)][string]$RelativePath)
    if ([IO.Path]::IsPathRooted($RelativePath)) { throw 'Expected a project-relative path.' }
    $full = [IO.Path]::GetFullPath((Join-Path $script:Root $RelativePath))
    $rootPrefix = $script:Root.TrimEnd([char[]]@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($rootPrefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Relative path escapes the project root.' }
    return $full
}

function Resolve-QueuedSourcePath {
    param([Parameter(Mandatory=$true)]$Item)
    if ($Item.PSObject.Properties.Name -contains 'source_rel_path' -and [string]$Item.source_rel_path) {
        return Resolve-ProjectRelativePath ([string]$Item.source_rel_path)
    }
    $legacy = [string]$Item.source_path
    if (-not $legacy) { throw 'Queued source path is missing.' }
    return [IO.Path]::GetFullPath($legacy)
}

function Resolve-IncomingStoredPath {
    param([Parameter(Mandatory=$true)]$Manifest,[ValidateSet('Part','Final')][string]$Kind)
    $relProperty = if ($Kind -eq 'Part') { 'part_rel_path' } else { 'final_rel_path' }
    $legacyProperty = if ($Kind -eq 'Part') { 'part_path' } else { 'final_path' }
    if ($Manifest.PSObject.Properties.Name -contains $relProperty -and [string]$Manifest.$relProperty) {
        return Resolve-ProjectRelativePath ([string]$Manifest.$relProperty)
    }
    $legacy = [string]$Manifest.$legacyProperty
    if ($legacy -and (Test-Path -LiteralPath $legacy)) { return [IO.Path]::GetFullPath($legacy) }
    if ($Kind -eq 'Part') { return Get-IncomingDataPath ([string]$Manifest.transfer_id) }
    $peerStub = [pscustomobject]@{ display_name=[string]$Manifest.from_name; peer_id=[string]$Manifest.from_peer_id }
    return (Join-Path (Join-Path $script:Paths.InboxFiles (Get-PeerSafeFolderName $peerStub)) ([string]$Manifest.final_name))
}

function Test-GuidText([string]$Value) {
    $g = [guid]::Empty
    return [guid]::TryParse($Value, [ref]$g)
}

function Test-PrivateIPv4 {
    param([Parameter(Mandatory=$true)][string]$Address)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $ip.GetAddressBytes()
    if ($b[0] -eq 10) { return $true }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $true }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $true }
    return $false
}

function Get-LocalPrivateIPv4s {
    $items = New-Object System.Collections.Generic.List[string]
    try {
        $addresses = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
            $_.IPAddress -and $_.IPAddress -ne '127.0.0.1' -and $_.AddressState -ne 'Duplicate'
        }
        foreach ($a in $addresses) {
            if (Test-PrivateIPv4 ([string]$a.IPAddress)) { [void]$items.Add([string]$a.IPAddress) }
        }
    } catch {
        try {
            foreach ($a in [Net.Dns]::GetHostAddresses([Net.Dns]::GetHostName())) {
                if (Test-PrivateIPv4 $a.IPAddressToString) { [void]$items.Add($a.IPAddressToString) }
            }
        } catch { }
    }
    return @($items.ToArray() | Select-Object -Unique | Sort-Object)
}

function Select-LocalPrivateIPv4 {
    param([switch]$NonInteractive)
    $cfg = Get-AppConfig
    $ips = @(Get-LocalPrivateIPv4s)
    if ($ips.Count -eq 0) { throw 'No RFC1918 private IPv4 address was found. Connect this PC to the trusted router network first.' }
    if ($cfg.preferred_ip -and ($ips -contains [string]$cfg.preferred_ip)) { return [string]$cfg.preferred_ip }
    if ($NonInteractive -or $ips.Count -eq 1) { return [string]$ips[0] }
    Write-Host ''
    Write-Host 'Private LAN addresses:'
    for ($i=0; $i -lt $ips.Count; $i++) { Write-Host ('  {0}. {1}' -f ($i+1), $ips[$i]) }
    $choice = Read-Host 'Choose the address reachable by the other PC'
    [int]$n = 0
    if (-not [int]::TryParse($choice, [ref]$n) -or $n -lt 1 -or $n -gt $ips.Count) { throw 'Invalid address selection.' }
    $selected = [string]$ips[$n-1]
    $cfg.preferred_ip = $selected
    Save-AppConfig $cfg
    return $selected
}

function Get-CertificateFingerprint {
    param([Parameter(Mandatory=$true)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    return Get-Sha256HexFromBytes -Bytes $Certificate.RawData
}


function Get-CertificateValidationInfo {
    param(
        [Parameter(Mandatory=$true)][Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$ExpectedFingerprint = '',
        [string]$ExpectedPeerId = ''
    )
    $fingerprint = Get-CertificateFingerprint $Certificate
    if ($ExpectedFingerprint -and -not [string]::Equals($fingerprint,$ExpectedFingerprint,[StringComparison]::OrdinalIgnoreCase)) {
        throw 'Certificate fingerprint does not match the pinned identity.'
    }
    $now = [DateTime]::UtcNow
    if ($now -lt $Certificate.NotBefore.ToUniversalTime().AddMinutes(-5)) { throw 'Certificate is not valid yet. Check both PCs clocks.' }
    if ($now -gt $Certificate.NotAfter.ToUniversalTime().AddMinutes(5)) { throw 'Certificate has expired. Re-pair through a trusted local workflow.' }
    if ($ExpectedPeerId) {
        if (-not (Test-GuidText $ExpectedPeerId)) { throw 'Expected certificate peer ID is invalid.' }
        $expectedName = 'LAN-Link-' + $ExpectedPeerId.ToLowerInvariant()
        $actualName = [string]$Certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
        if (-not [string]::Equals($actualName,$expectedName,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'Certificate subject does not match the expected peer identity.'
        }
    }
    if ([string]$Certificate.PublicKey.Oid.Value -ne '1.2.840.113549.1.1.1') { throw 'Only RSA identity certificates are supported.' }
    [int]$keySize = 0
    try { $keySize = [int]$Certificate.PublicKey.Key.KeySize } catch { throw 'Could not inspect the identity certificate public key.' }
    if ($keySize -lt 2048) { throw 'Identity certificate RSA key is below the 2048-bit safety floor.' }
    return [pscustomobject]@{
        fingerprint       = $fingerprint
        simple_name       = [string]$Certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
        key_algorithm_oid = [string]$Certificate.PublicKey.Oid.Value
        key_size          = $keySize
        not_before_utc    = $Certificate.NotBefore.ToUniversalTime().ToString('o')
        not_after_utc     = $Certificate.NotAfter.ToUniversalTime().ToString('o')
    }
}

function Get-CertificateInfoFromDer {
    param(
        [Parameter(Mandatory=$true)][byte[]]$DerBytes,
        [string]$ExpectedFingerprint = '',
        [string]$ExpectedPeerId = ''
    )
    if ($DerBytes.Length -lt 128 -or $DerBytes.Length -gt 65536) { throw 'Certificate DER size is outside supported limits.' }
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($DerBytes)
    try { return Get-CertificateValidationInfo -Certificate $cert -ExpectedFingerprint $ExpectedFingerprint -ExpectedPeerId $ExpectedPeerId }
    finally { $cert.Dispose() }
}

function New-IdentityCertificateBytes {
    param([string]$PeerId, [string]$Password)
    try {
        $rsa = [Security.Cryptography.RSA]::Create()
        $rsa.KeySize = 3072
        try {
            $dn = [Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=LAN-Link-$PeerId")
            $req = [Security.Cryptography.X509Certificates.CertificateRequest]::new(
                $dn,
                $rsa,
                [Security.Cryptography.HashAlgorithmName]::SHA256,
                [Security.Cryptography.RSASignaturePadding]::Pkcs1
            )
            $req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true))
            $req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
                [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
                $true
            ))
            $oids = [Security.Cryptography.OidCollection]::new()
            [void]$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1','Server Authentication'))
            [void]$oids.Add([Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2','Client Authentication'))
            $req.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false))
            $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddYears(5))
            try {
                $pfx = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $Password)
                return ,$pfx
            } finally { $cert.Dispose() }
        } finally { $rsa.Dispose() }
    } catch {
        Write-AppLog -Level WARN -Message ('CertificateRequest path unavailable; using CurrentUser certificate cmdlets. ' + $_.Exception.Message)
        $subject = "CN=LAN-Link-$PeerId"
        $cert = New-SelfSignedCertificate -Subject $subject -CertStoreLocation 'Cert:\CurrentUser\My' `
            -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyExportPolicy Exportable `
            -KeyUsage DigitalSignature -NotAfter ([DateTime]::UtcNow.AddYears(5)) `
            -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1&1.3.6.1.5.5.7.3.2')
        try {
            $secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
            $tmp = Join-Path $script:Paths.Temp ('cert-' + [guid]::NewGuid().ToString('N') + '.pfx')
            [void](Export-PfxCertificate -Cert $cert -FilePath $tmp -Password $secure -Force)
            try { $pfx = [IO.File]::ReadAllBytes($tmp); return ,$pfx } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        } finally {
            Remove-Item -LiteralPath ('Cert:\CurrentUser\My\' + $cert.Thumbprint) -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-IdentityPath { return (Join-Path $script:Paths.Identity 'identity.json') }
function Get-PfxPath { return (Join-Path $script:Paths.Identity 'server.pfx') }

function New-LocalIdentity {
    $peerId = [guid]::NewGuid().ToString('D')
    $displayName = if ($env:COMPUTERNAME) { [string]$env:COMPUTERNAME } else { [Net.Dns]::GetHostName() }
    $password = [Convert]::ToBase64String((New-RandomBytes 32))
    $pfxBytes = New-IdentityCertificateBytes -PeerId $peerId -Password $password
    Write-DurableBytes -Path (Get-PfxPath) -Bytes $pfxBytes
    $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor `
             [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxBytes, $password, $flags)
    try {
        $identity = [ordered]@{
            schema                 = 'lanlink-identity-v2'
            peer_id                = $peerId
            display_name           = $displayName
            machine_name           = [Net.Dns]::GetHostName()
            created_utc            = Get-UtcIso
            cert_sha256            = Get-CertificateFingerprint $cert
            cert_not_after_utc     = $cert.NotAfter.ToUniversalTime().ToString('o')
            pfx_password_protected = Protect-TextToBase64 $password
        }
        Write-JsonFile -Path (Get-IdentityPath) -Object $identity
        Write-Info "Created this PC's LAN Router Comms identity: $displayName"
        return [pscustomobject]$identity
    } finally { $cert.Dispose() }
}

function Get-LocalIdentity {
    $identityPath = Get-IdentityPath
    $pfxPath = Get-PfxPath
    $hasIdentity = Test-Path -LiteralPath $identityPath -PathType Leaf
    $hasPfx = Test-Path -LiteralPath $pfxPath -PathType Leaf
    if ($hasIdentity -xor $hasPfx) {
        throw 'Local identity is incomplete (identity.json and server.pfx must exist together). The program refused silent identity rotation. Preserve state, restore the missing file from the same trusted backup, or start fresh in a new folder and re-pair.'
    }
    if (-not $hasIdentity -and -not $hasPfx) {
        $mutex = Enter-ProjectMutex -Purpose 'IdentityInitialization' -TimeoutMs 30000
        try {
            $hasIdentity = Test-Path -LiteralPath $identityPath -PathType Leaf
            $hasPfx = Test-Path -LiteralPath $pfxPath -PathType Leaf
            if ($hasIdentity -xor $hasPfx) { throw 'Local identity became incomplete during initialization; no identity was overwritten.' }
            if (-not $hasIdentity -and -not $hasPfx) { return New-LocalIdentity }
        } finally { Exit-ProjectMutex $mutex }
    }
    $identity = Read-JsonFile -Path $identityPath
    if ($identity.schema -ne 'lanlink-identity-v2' -or -not (Test-GuidText ([string]$identity.peer_id))) {
        throw 'Local identity is invalid. Use the recovery instructions; do not delete peer state blindly.'
    }
    return $identity
}

function Get-IdentityCertificate {
    $identity = Get-LocalIdentity
    $password = Unprotect-Base64ToText ([string]$identity.pfx_password_protected)
    $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor `
             [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new((Get-PfxPath), $password, $flags)
    try {
        [void](Get-CertificateValidationInfo -Certificate $cert -ExpectedFingerprint ([string]$identity.cert_sha256) -ExpectedPeerId ([string]$identity.peer_id))
        return $cert
    } catch {
        $cert.Dispose()
        throw
    }
}

function Get-PeerPath([string]$PeerId) {
    if (-not (Test-GuidText $PeerId)) { throw 'Peer ID is invalid.' }
    return (Join-Path $script:Paths.Peers ($PeerId.ToLowerInvariant() + '.json'))
}

function Save-Peer($Peer) {
    if (-not (Test-GuidText ([string]$Peer.peer_id))) { throw 'Cannot save a peer with an invalid ID.' }
    $mutex = Enter-ProjectMutex -Purpose 'PeerState' -TimeoutMs 15000
    try { Write-JsonFile -Path (Get-PeerPath ([string]$Peer.peer_id)) -Object $Peer }
    finally { Exit-ProjectMutex $mutex }
}


function Get-Peer {
    param([string]$PeerId,[switch]$AllowDisabled)
    $path = Get-PeerPath $PeerId
    if (-not (Test-Path -LiteralPath $path)) { throw 'Paired peer not found.' }
    $peer = Read-JsonFile -Path $path
    if ($peer.schema -ne 'lanlink-peer-v2' -or -not (Test-GuidText ([string]$peer.peer_id))) { throw 'Peer record is invalid.' }
    if (-not $AllowDisabled -and $peer.enabled -eq $false) { throw 'This peer is disabled. Create a fresh pairing invitation to restore access intentionally.' }
    return $peer
}

function Update-PeerActivity {
    param([Parameter(Mandatory=$true)][string]$PeerId,[string]$SuccessfulIp='')
    $mutex = Enter-ProjectMutex -Purpose 'PeerState' -TimeoutMs 15000
    try {
        $latest = Get-Peer -PeerId $PeerId -AllowDisabled
        $latest.last_seen_utc = Get-UtcIso
        if ($SuccessfulIp -and (Test-PrivateIPv4 $SuccessfulIp)) { $latest.last_success_ip = $SuccessfulIp }
        # Preserve the latest enabled/disabled state so activity cannot undo a concurrent revocation.
        Write-JsonFile -Path (Get-PeerPath $PeerId) -Object $latest
        return $latest
    } finally { Exit-ProjectMutex $mutex }
}

function Disable-PeerRecord {
    param([Parameter(Mandatory=$true)][string]$PeerId)
    $mutex = Enter-ProjectMutex -Purpose 'PeerState' -TimeoutMs 15000
    try {
        $latest = Get-Peer -PeerId $PeerId -AllowDisabled
        $latest.enabled = $false
        $latest.disabled_utc = Get-UtcIso
        Write-JsonFile -Path (Get-PeerPath $PeerId) -Object $latest
        return $latest
    } finally { Exit-ProjectMutex $mutex }
}


function Get-AllPeerRecords {
    param([switch]$ReadOnly)
    $result = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $script:Paths.Peers -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try {
            $p = Read-JsonFile $f.FullName
            if ($p.schema -eq 'lanlink-peer-v2' -and (Test-GuidText ([string]$p.peer_id))) { $result += $p }
            elseif (-not $ReadOnly) { Write-AppLog -Level WARN -Message "Skipped invalid peer record $($f.Name)." }
        } catch { if (-not $ReadOnly) { Write-AppLog -Level WARN -Message "Skipped corrupt peer record $($f.Name)." } }
    }
    return @($result)
}

function Get-AllPeers {
    return @(Get-AllPeerRecords | Where-Object { $_.enabled -ne $false })
}

function Get-PeerSecret([object]$Peer) {
    return Unprotect-Base64ToBytes ([string]$Peer.shared_secret_protected)
}

function Select-Peer {
    $peers = @(Get-AllPeers)
    if ($peers.Count -eq 0) { throw 'No paired PCs are available. Create or import a pairing invitation first.' }
    Write-Host ''
    Write-Host 'Paired PCs:'
    for ($i=0; $i -lt $peers.Count; $i++) {
        $last = if ($peers[$i].last_seen_utc) { [string]$peers[$i].last_seen_utc } else { 'never' }
        Write-Host ('  {0}. {1}  ({2}, last seen {3})' -f ($i+1), $peers[$i].display_name, $peers[$i].endpoint_ip, $last)
    }
    $choice = Read-Host 'Choose a PC'
    [int]$n = 0
    if (-not [int]::TryParse($choice, [ref]$n) -or $n -lt 1 -or $n -gt $peers.Count) { throw 'Invalid peer selection.' }
    return $peers[$n-1]
}


function Show-PeerManagement {
    while ($true) {
        $records = @(Get-AllPeerRecords)
        Write-Host ''
        Write-Host 'Paired PC management' -ForegroundColor Cyan
        if (-not $records.Count) { Write-Host '  No peer records exist.' }
        for ($i=0; $i -lt $records.Count; $i++) {
            $status = if ($records[$i].enabled -eq $false) { 'DISABLED' } else { 'ENABLED' }
            Write-Host ('  {0}. {1} [{2}] last seen {3}' -f ($i+1),$records[$i].display_name,$status,$records[$i].last_seen_utc)
        }
        Write-Host '  D. Disable/revoke an enabled peer'
        Write-Host '  0. Back'
        $choice = Read-Host 'Choose'
        if ($choice -eq '0') { return }
        if ($choice -match '^[Dd]$') {
            $enabled = @(Get-AllPeers)
            if (-not $enabled.Count) { Write-Warn 'No enabled peers are available.'; continue }
            for ($i=0; $i -lt $enabled.Count; $i++) { Write-Host ('  {0}. {1}' -f ($i+1),$enabled[$i].display_name) }
            [int]$n = 0
            $pick = Read-Host 'Choose the peer to disable'
            if (-not [int]::TryParse($pick,[ref]$n) -or $n -lt 1 -or $n -gt $enabled.Count) { Write-Warn 'Invalid selection.'; continue }
            $confirm = Read-Host "Type DISABLE to revoke $($enabled[$n-1].display_name)"
            if ($confirm -cne 'DISABLE') { Write-Warn 'No change made.'; continue }
            $peer = Disable-PeerRecord -PeerId ([string]$enabled[$n-1].peer_id)
            Write-Info "Disabled $($peer.display_name). Existing history was preserved."
        } else { Write-Warn 'Invalid choice.' }
    }
}

function Get-CanonicalEnvelopeText($Envelope) {
    return (@(
        [string]$Envelope.schema,
        [string]$Envelope.operation,
        [string]$Envelope.sender_peer_id,
        [string]$Envelope.request_id,
        [string]$Envelope.correlation_id,
        [string]$Envelope.timestamp_utc,
        [string]$Envelope.nonce_b64,
        [string]$Envelope.payload_b64
    ) -join "`n")
}

function New-AuthEnvelope {
    param(
        [string]$Operation,
        [string]$SenderPeerId,
        [Parameter(Mandatory=$true)]$Payload,
        [byte[]]$Secret,
        [string]$CorrelationId = ''
    )
    if (-not (Test-GuidText $SenderPeerId)) { throw 'Sender identity is invalid.' }
    $payloadJson = ConvertTo-CompactJson -InputObject $Payload -Depth 16
    $env = [ordered]@{
        schema         = 'lanlink-envelope-v2'
        operation      = $Operation
        sender_peer_id = $SenderPeerId.ToLowerInvariant()
        request_id     = [guid]::NewGuid().ToString('D')
        correlation_id = [string]$CorrelationId
        timestamp_utc  = Get-UtcIso
        nonce_b64      = [Convert]::ToBase64String((New-RandomBytes 18))
        payload_b64    = [Convert]::ToBase64String($script:Utf8NoBom.GetBytes($payloadJson))
        mac_b64        = ''
    }
    $canonical = Get-CanonicalEnvelopeText $env
    $h = [Security.Cryptography.HMACSHA256]::new($Secret)
    try { $mac = $h.ComputeHash($script:Utf8NoBom.GetBytes($canonical)) } finally { $h.Dispose() }
    $env.mac_b64 = [Convert]::ToBase64String($mac)
    return [pscustomobject]$env
}

function Read-UntrustedEnvelopePayload {
    param($Envelope)
    if ($Envelope.schema -ne 'lanlink-envelope-v2') { throw 'Unsupported protocol envelope.' }
    $payloadBytes = [Convert]::FromBase64String([string]$Envelope.payload_b64)
    if ($payloadBytes.Length -gt $script:MaxFrameBytes) { throw 'Envelope payload is too large.' }
    $json = [Text.Encoding]::UTF8.GetString($payloadBytes)
    return ($json | ConvertFrom-Json)
}

function Assert-EnvelopeAuth {
    param(
        $Envelope,
        [byte[]]$Secret,
        [string]$ExpectedSenderPeerId = '',
        [string]$ExpectedCorrelationId = ''
    )
    if ($Envelope.schema -ne 'lanlink-envelope-v2') { throw 'Unsupported protocol envelope.' }
    if (-not (Test-GuidText ([string]$Envelope.sender_peer_id)) -or -not (Test-GuidText ([string]$Envelope.request_id))) { throw 'Envelope IDs are invalid.' }
    if ($ExpectedSenderPeerId -and -not [string]::Equals([string]$Envelope.sender_peer_id,$ExpectedSenderPeerId,[StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected sender identity.' }
    if ($ExpectedCorrelationId -and -not [string]::Equals([string]$Envelope.correlation_id,$ExpectedCorrelationId,[StringComparison]::OrdinalIgnoreCase)) { throw 'Response correlation failed.' }
    $timestamp = [DateTime]::MinValue
    if (-not [DateTime]::TryParse([string]$Envelope.timestamp_utc, $null, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$timestamp)) { throw 'Envelope timestamp is invalid.' }
    $cfg = Get-AppConfig
    $skew = [Math]::Abs(([DateTime]::UtcNow - $timestamp.ToUniversalTime()).TotalSeconds)
    if ($skew -gt [int]$cfg.max_clock_skew_seconds) { throw 'Envelope timestamp is outside the allowed clock-skew window. Check both PCs clocks.' }
    $nonce = [Convert]::FromBase64String([string]$Envelope.nonce_b64)
    if ($nonce.Length -lt 16) { throw 'Envelope nonce is invalid.' }
    $provided = [Convert]::FromBase64String([string]$Envelope.mac_b64)
    $h = [Security.Cryptography.HMACSHA256]::new($Secret)
    try { $expected = $h.ComputeHash($script:Utf8NoBom.GetBytes((Get-CanonicalEnvelopeText $Envelope))) } finally { $h.Dispose() }
    if (-not (Test-FixedTimeEqual $provided $expected)) { throw 'Envelope authentication failed.' }
    return Read-UntrustedEnvelopePayload $Envelope
}

function Write-Frame {
    param([IO.Stream]$Stream, [Parameter(Mandatory=$true)]$Object)
    $json = ConvertTo-CompactJson -InputObject $Object -Depth 18
    $bytes = $script:Utf8NoBom.GetBytes($json)
    if ($bytes.Length -lt 1 -or $bytes.Length -gt $script:MaxFrameBytes) { throw 'Outgoing frame size is invalid.' }
    $netLength = [Net.IPAddress]::HostToNetworkOrder([int]$bytes.Length)
    $header = [BitConverter]::GetBytes($netLength)
    $Stream.Write($header,0,4)
    $Stream.Write($bytes,0,$bytes.Length)
    $Stream.Flush()
}

function Read-ExactBytes {
    param([IO.Stream]$Stream, [int]$Count)
    $buffer = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer,$offset,$Count-$offset)
        if ($read -le 0) { throw 'Connection closed before the frame completed.' }
        $offset += $read
    }
    return ,$buffer
}

function Read-Frame {
    param([IO.Stream]$Stream)
    $header = Read-ExactBytes -Stream $Stream -Count 4
    $length = [Net.IPAddress]::NetworkToHostOrder([BitConverter]::ToInt32($header,0))
    if ($length -lt 1 -or $length -gt $script:MaxFrameBytes) { throw "Incoming frame length $length is outside limits." }
    $bytes = Read-ExactBytes -Stream $Stream -Count $length
    $json = [Text.Encoding]::UTF8.GetString($bytes)
    return ($json | ConvertFrom-Json)
}

function Get-PeerEndpointCandidates($Peer) {
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($v in @([string]$Peer.last_success_ip, [string]$Peer.endpoint_ip, [string]$Peer.claimed_ip)) {
        if ($v -and (Test-PrivateIPv4 $v) -and -not $candidates.Contains($v)) { [void]$candidates.Add($v) }
    }
    if ($Peer.machine_name) {
        try {
            foreach ($ip in [Net.Dns]::GetHostAddresses([string]$Peer.machine_name)) {
                $s = $ip.IPAddressToString
                if ((Test-PrivateIPv4 $s) -and -not $candidates.Contains($s)) { [void]$candidates.Add($s) }
            }
        } catch { }
    }
    return $candidates.ToArray()
}

function Open-TlsPinnedSession {
    param(
        [string[]]$Addresses,
        [int]$Port,
        [string]$ExpectedFingerprint,
        [string]$ExpectedPeerId
    )
    $cfg = Get-AppConfig
    $lastError = $null
    foreach ($address in $Addresses) {
        if (-not (Test-PrivateIPv4 $address)) { continue }
        $client = $null
        $ssl = $null
        $ar = $null
        try {
            $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork)
            $client.NoDelay = $true
            $client.ReceiveTimeout = [int]$cfg.io_timeout_ms
            $client.SendTimeout = [int]$cfg.io_timeout_ms
            $ar = $client.BeginConnect($address,$Port,$null,$null)
            try {
                if (-not $ar.AsyncWaitHandle.WaitOne([int]$cfg.connect_timeout_ms,$false)) {
                    $client.Close(); throw "Connection to $address timed out."
                }
                $client.EndConnect($ar)
                $keepAliveApplied = Set-TcpKeepAlive -TcpClient $client -Config $cfg
            } finally {
                if ($ar -and $ar.AsyncWaitHandle) { try { $ar.AsyncWaitHandle.Close() } catch { } }
            }
            $expected = $ExpectedFingerprint.ToLowerInvariant()
            $expectedPeer = $ExpectedPeerId.ToLowerInvariant()
            $callbackBlock = {
                param($sender,$certificate,$chain,$sslPolicyErrors)
                try {
                    $c = [Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
                    try {
                        $sha = [Security.Cryptography.SHA256]::Create()
                        try { $rawHash = $sha.ComputeHash($c.RawData) } finally { $sha.Dispose() }
                        $actual = (($rawHash | ForEach-Object { $_.ToString('x2') }) -join '')
                        if (-not [string]::Equals($actual,$expected,[StringComparison]::OrdinalIgnoreCase)) { return $false }
                        $now = [DateTime]::UtcNow
                        if ($now -lt $c.NotBefore.ToUniversalTime().AddMinutes(-5) -or $now -gt $c.NotAfter.ToUniversalTime().AddMinutes(5)) { return $false }
                        $name = [string]$c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
                        return [string]::Equals($name,('LAN-Link-' + $expectedPeer),[StringComparison]::OrdinalIgnoreCase)
                    } finally { $c.Dispose() }
                } catch { return $false }
            }.GetNewClosure()
            $callback = [Net.Security.RemoteCertificateValidationCallback]$callbackBlock
            $ssl = [Net.Security.SslStream]::new($client.GetStream(),$false,$callback)
            $ssl.ReadTimeout = [int]$cfg.io_timeout_ms
            $ssl.WriteTimeout = [int]$cfg.io_timeout_ms
            $ssl.AuthenticateAsClient(("LAN-Link-$ExpectedPeerId"),$null,$script:TlsProtocols,$false)
            if (-not (Test-AcceptableTlsProtocol $ssl.SslProtocol)) { throw ('Negotiated TLS protocol is below the TLS 1.2 minimum: ' + [string]$ssl.SslProtocol) }
            return [pscustomobject]@{ Client=$client; Stream=$ssl; Address=$address; TlsProtocol=(Get-TlsProtocolLabel $ssl.SslProtocol); KeepAlive=[bool]$keepAliveApplied }
        } catch {
            $lastError = $_.Exception.Message
            if ($ssl) { $ssl.Dispose() }
            if ($client) { $client.Close() }
        }
    }
    if (-not $lastError) { $lastError = 'No valid private endpoint candidates were available.' }
    throw $lastError
}

function Close-TlsSession($Session) {
    if ($null -ne $Session) {
        try { $Session.Stream.Dispose() } catch { }
        try { $Session.Client.Close() } catch { }
    }
}

function Invoke-SessionRequest {
    param(
        $Session,
        $Peer,
        [byte[]]$Secret,
        [string]$Operation,
        [Parameter(Mandatory=$true)]$Payload
    )
    $identity = Get-LocalIdentity
    $request = New-AuthEnvelope -Operation $Operation -SenderPeerId ([string]$identity.peer_id) -Payload $Payload -Secret $Secret
    Write-Frame -Stream $Session.Stream -Object $request
    $response = Read-Frame -Stream $Session.Stream
    $responsePayload = Assert-EnvelopeAuth -Envelope $response -Secret $Secret -ExpectedSenderPeerId ([string]$Peer.peer_id) -ExpectedCorrelationId ([string]$request.request_id)
    if ($responsePayload.ok -ne $true) {
        $msg = if ($responsePayload.message) { [string]$responsePayload.message } else { 'The peer rejected the request.' }
        throw $msg
    }
    return $responsePayload
}

function Invoke-PeerRequest {
    param($Peer, [string]$Operation, [Parameter(Mandatory=$true)]$Payload)
    $secret = Get-PeerSecret $Peer
    $addresses = @(Get-PeerEndpointCandidates $Peer)
    if ($addresses.Count -eq 0) { throw 'No valid private endpoint is stored for this peer.' }
    $session = Open-TlsPinnedSession -Addresses $addresses -Port ([int]$Peer.port) -ExpectedFingerprint ([string]$Peer.cert_sha256) -ExpectedPeerId ([string]$Peer.peer_id)
    try {
        $reply = Invoke-SessionRequest -Session $session -Peer $Peer -Secret $secret -Operation $Operation -Payload $Payload
        [void](Update-PeerActivity -PeerId ([string]$Peer.peer_id) -SuccessfulIp ([string]$session.Address))
        Write-AppLog -Level INFO -Message "Authenticated peer session tls=$($session.TlsProtocol) peer=$($Peer.peer_id) address=$($session.Address)."
        return $reply
    } finally { Close-TlsSession $session }
}

function Get-InviteStatePath([string]$InviteId) {
    if (-not (Test-GuidText $InviteId)) { throw 'Invitation ID is invalid.' }
    return (Join-Path $script:Paths.Invites ($InviteId.ToLowerInvariant() + '.json'))
}

function New-PairingInvite {
    $identity = Get-LocalIdentity
    $cert = Get-IdentityCertificate
    try { $certDer = [Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
    finally { $cert.Dispose() }
    $cfg = Get-AppConfig
    $ip = Select-LocalPrivateIPv4
    $minutesText = Read-Host 'Invite lifetime in minutes [15]'
    [int]$minutes = 15
    if ($minutesText -and (-not [int]::TryParse($minutesText,[ref]$minutes) -or $minutes -lt 2 -or $minutes -gt 1440)) { throw 'Invite lifetime must be from 2 to 1440 minutes.' }
    $inviteId = [guid]::NewGuid().ToString('D')
    $secret = New-RandomBytes 32
    $expires = [DateTime]::UtcNow.AddMinutes($minutes).ToString('o')
    $state = [ordered]@{
        schema                    = 'lanlink-invite-state-v2'
        invite_id                 = $inviteId
        created_utc               = Get-UtcIso
        expires_utc               = $expires
        secret_protected          = Protect-BytesToBase64 $secret
        used_by_peer_id           = ''
        shared_secret_protected   = ''
        paired_utc                = ''
        export_rel_path           = ''
    }
    Write-JsonFile -Path (Get-InviteStatePath $inviteId) -Object $state
    $invite = [ordered]@{
        schema               = 'lanlink-invite-v2'
        protocol_version     = $script:ProtocolVersion
        invite_id            = $inviteId
        issuer_peer_id       = [string]$identity.peer_id
        issuer_name          = [string]$identity.display_name
        issuer_machine_name  = [string]$identity.machine_name
        issuer_ip            = $ip
        issuer_port          = [int]$cfg.listen_port
        expires_utc          = $expires
        issuer_cert_sha256   = [string]$identity.cert_sha256
        issuer_cert_der_b64  = $certDer
        invite_secret_b64    = [Convert]::ToBase64String($secret)
        capabilities         = @($script:Capabilities)
    }
    $safeName = ([string]$identity.display_name -replace '[^A-Za-z0-9_.-]','_')
    $out = Join-Path $script:Paths.Exports ('Pair_' + $safeName + '_' + [DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss') + '.llinvite')
    $inviteJson = ConvertTo-CompactJson $invite 16
    Write-DurableText -Path $out -Text $inviteJson
    $state.export_rel_path = Get-ProjectRelativePath $out
    Write-JsonFile -Path (Get-InviteStatePath $inviteId) -Object $state
    $code = (Get-Sha256HexFromBytes $script:Utf8NoBom.GetBytes($inviteJson)).Substring(0,12).ToUpperInvariant()
    Write-Host ''
    Write-Info "Pairing invitation created: $out"
    Write-Host "Verification code: $code"
    Write-Warn 'The invitation is a short-lived secret. Transfer it directly to the other PC and do not post it publicly.'
    Write-Host "It expires at $expires UTC and works for one peer."
    $start = Read-Host 'Open the visible receiver window now? [Y/n]'
    if (-not $start -or $start -match '^[Yy]') { Start-ReceiverWindow -Port ([int]$cfg.listen_port) }
}

function Import-PairingInvite {
    $path = Read-Host 'Full path to the .llinvite file'
    $path = $path.Trim('"')
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Invitation file was not found.' }
    $inviteRaw = [IO.File]::ReadAllText($path,[Text.Encoding]::UTF8)
    $invite = $inviteRaw | ConvertFrom-Json
    if ($invite.schema -ne 'lanlink-invite-v2' -or [int]$invite.protocol_version -ne 2) { throw 'This is not a supported LAN Router Comms v2 invitation.' }
    $verifyCode = (Get-Sha256HexFromBytes $script:Utf8NoBom.GetBytes($inviteRaw)).Substring(0,12).ToUpperInvariant()
    Write-Host ''
    Write-Host ('Invitation from: {0} at {1}:{2}' -f $invite.issuer_name,$invite.issuer_ip,$invite.issuer_port)
    Write-Host ('Verification code: ' + $verifyCode)
    Write-Host ('Expires UTC: ' + $invite.expires_utc)
    $confirm = Read-Host 'Compare the code with the issuer PC. Type PAIR to trust this PC and delete this invitation after success'
    if ($confirm -cne 'PAIR') { throw 'Pairing was cancelled; no trust record was changed.' }
    if (-not (Test-GuidText ([string]$invite.invite_id)) -or -not (Test-GuidText ([string]$invite.issuer_peer_id))) { throw 'Invitation IDs are invalid.' }
    $expiry = ConvertTo-UtcDateTime ([string]$invite.expires_utc)
    if ([DateTime]::UtcNow -gt $expiry) { throw 'This pairing invitation has expired.' }
    if (-not (Test-PrivateIPv4 ([string]$invite.issuer_ip))) { throw 'Invitation endpoint is not a private IPv4 address.' }
    if ([int]$invite.issuer_port -lt 1 -or [int]$invite.issuer_port -gt 65535) { throw 'Invitation port is invalid.' }
    $der = [Convert]::FromBase64String([string]$invite.issuer_cert_der_b64)
    $issuerCertInfo = Get-CertificateInfoFromDer -DerBytes $der -ExpectedFingerprint ([string]$invite.issuer_cert_sha256) -ExpectedPeerId ([string]$invite.issuer_peer_id)
    $derivedFp = [string]$issuerCertInfo.fingerprint
    $inviteSecret = [Convert]::FromBase64String([string]$invite.invite_secret_b64)
    if ($inviteSecret.Length -ne 32) { throw 'Invitation secret is invalid.' }
    $identity = Get-LocalIdentity
    $cert = Get-IdentityCertificate
    try { $ourCertDer = [Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
    finally { $cert.Dispose() }
    $cfg = Get-AppConfig
    $ourIp = Select-LocalPrivateIPv4
    $payload = [ordered]@{
        invite_id           = [string]$invite.invite_id
        peer_id             = [string]$identity.peer_id
        display_name        = [string]$identity.display_name
        machine_name        = [string]$identity.machine_name
        listen_ip           = $ourIp
        listen_port         = [int]$cfg.listen_port
        cert_sha256         = [string]$identity.cert_sha256
        cert_der_b64        = $ourCertDer
        capabilities        = @($script:Capabilities)
    }
    $request = New-AuthEnvelope -Operation 'pair.request' -SenderPeerId ([string]$identity.peer_id) -Payload $payload -Secret $inviteSecret
    $session = Open-TlsPinnedSession -Addresses @([string]$invite.issuer_ip) -Port ([int]$invite.issuer_port) -ExpectedFingerprint ([string]$invite.issuer_cert_sha256) -ExpectedPeerId ([string]$invite.issuer_peer_id)
    try {
        Write-Frame -Stream $session.Stream -Object $request
        $response = Read-Frame -Stream $session.Stream
        $reply = Assert-EnvelopeAuth -Envelope $response -Secret $inviteSecret -ExpectedSenderPeerId ([string]$invite.issuer_peer_id) -ExpectedCorrelationId ([string]$request.request_id)
        if ($reply.ok -ne $true) { throw ([string]$reply.message) }
        $shared = [Convert]::FromBase64String([string]$reply.shared_secret_b64)
        if ($shared.Length -ne 32) { throw 'Pairing response contained an invalid shared secret.' }
        $replyDer = [Convert]::FromBase64String([string]$reply.cert_der_b64)
        $replyCertInfo = Get-CertificateInfoFromDer -DerBytes $replyDer -ExpectedFingerprint ([string]$invite.issuer_cert_sha256) -ExpectedPeerId ([string]$invite.issuer_peer_id)
        $replyFp = [string]$replyCertInfo.fingerprint
        $peer = [ordered]@{
            schema                    = 'lanlink-peer-v2'
            peer_id                   = [string]$invite.issuer_peer_id
            display_name              = [string]$reply.display_name
            machine_name              = [string]$reply.machine_name
            endpoint_ip               = [string]$invite.issuer_ip
            claimed_ip                = [string]$reply.listen_ip
            last_success_ip           = [string]$session.Address
            port                      = [int]$reply.listen_port
            cert_sha256               = [string]$invite.issuer_cert_sha256
            cert_der_b64              = [string]$reply.cert_der_b64
            cert_not_after_utc         = [string]$replyCertInfo.not_after_utc
            shared_secret_protected   = Protect-BytesToBase64 $shared
            paired_utc                = Get-UtcIso
            last_seen_utc             = Get-UtcIso
            enabled                   = $true
            capabilities              = @($reply.capabilities)
        }
        Save-Peer $peer
        try { Remove-Item -LiteralPath $path -Force -ErrorAction Stop; Write-Info 'The imported invitation file was deleted after successful pairing.' } catch { Write-Warn 'Pairing succeeded, but the imported invitation file could not be deleted. Remove it manually.' }
        Write-Info "Paired with $($peer.display_name)."
        Write-Host 'The peer is pinned by certificate fingerprint and a per-peer authentication key.'
    } finally { Close-TlsSession $session }
}

function Get-ReplayPath([string]$PeerId,[string]$RequestId) {
    if (-not (Test-GuidText $PeerId) -or -not (Test-GuidText $RequestId)) { throw 'Replay marker IDs are invalid.' }
    $dir = Join-Path $script:Paths.Replay $PeerId.ToLowerInvariant()
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    return (Join-Path $dir ($RequestId.ToLowerInvariant() + '.seen'))
}

function Test-ReplaySeen([string]$PeerId,[string]$RequestId) {
    return (Test-Path -LiteralPath (Get-ReplayPath $PeerId $RequestId))
}

function Mark-ReplaySeen([string]$PeerId,[string]$RequestId,[string]$Operation) {
    Write-DurableText -Path (Get-ReplayPath $PeerId $RequestId) -Text ((Get-UtcIso) + "`t" + $Operation)
}


function Get-SafeLeafName([string]$Name) {
    $leaf = [IO.Path]::GetFileName($Name)
    foreach ($ch in [IO.Path]::GetInvalidFileNameChars()) { $leaf = $leaf.Replace([string]$ch,'_') }
    $leaf = $leaf.Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = 'received_file' }
    $stem = [IO.Path]::GetFileNameWithoutExtension($leaf)
    if ($stem -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { $leaf = '_' + $leaf }
    if ($leaf.Length -gt 180) {
        $ext = [IO.Path]::GetExtension($leaf)
        $base = [IO.Path]::GetFileNameWithoutExtension($leaf)
        $leaf = $base.Substring(0,[Math]::Min(150,$base.Length)) + $ext
    }
    return $leaf
}

function Get-PeerSafeFolderName($Peer) {
    $name = ([string]$Peer.display_name -replace '[^A-Za-z0-9_.-]','_').Trim('_')
    if (-not $name) { $name = 'peer' }
    return ($name + '_' + ([string]$Peer.peer_id).Substring(0,8))
}

function Receive-TextMessage {
    param($Peer,$Payload)
    if (-not (Test-GuidText ([string]$Payload.message_id))) { throw 'Message ID is invalid.' }
    $text = [string]$Payload.text
    $cfg = Get-AppConfig
    $bytes = $script:Utf8NoBom.GetBytes($text)
    if ($bytes.Length -lt 1 -or $bytes.Length -gt [int]$cfg.max_message_bytes) { throw 'Message size is outside the configured limit.' }
    $dir = Join-Path $script:Paths.DedupeMessages ([string]$Peer.peer_id)
    if (-not (Test-Path -LiteralPath $dir)) { [void](New-Item -ItemType Directory -Path $dir -Force) }
    $dedupe = Join-Path $dir (([string]$Payload.message_id).ToLowerInvariant() + '.json')
    $duplicate = Test-Path -LiteralPath $dedupe
    $name = (([string]$Peer.peer_id).Substring(0,8) + '_' + ([string]$Payload.message_id).ToLowerInvariant() + '.llmsg')
    $inboxPath = Join-Path $script:Paths.InboxMessages $name
    if (-not $duplicate) {
        if (Test-Path -LiteralPath $inboxPath) {
            $existing = Read-JsonFile $inboxPath
            if ($existing.message_id -ne $Payload.message_id -or $existing.from_peer_id -ne $Peer.peer_id) { throw 'Deterministic inbox path conflicts with another message.' }
            $duplicate = $true
            $receivedUtc = [string]$existing.received_utc
        } else {
            $item = [ordered]@{
                schema          = 'lanlink-message-v2'
                message_id      = [string]$Payload.message_id
                from_peer_id    = [string]$Peer.peer_id
                from_name       = [string]$Peer.display_name
                sent_utc        = [string]$Payload.sent_utc
                received_utc    = Get-UtcIso
                text_protected  = Protect-TextToBase64 $text
            }
            Write-JsonFile -Path $inboxPath -Object $item
            $receivedUtc = [string]$item.received_utc
            Write-Host ''
            Write-Host ('MESSAGE from {0}: {1}' -f $Peer.display_name, $text) -ForegroundColor Cyan
            try { [Console]::Beep(850,120) } catch { }
        }
        Write-JsonFile -Path $dedupe -Object ([ordered]@{ message_id=$Payload.message_id; inbox_file=$name; received_utc=$receivedUtc })
    } else {
        $marker = Read-JsonFile $dedupe
        $receivedUtc = [string]$marker.received_utc
    }
    return [ordered]@{ ok=$true; status='delivered'; message_id=[string]$Payload.message_id; duplicate=$duplicate; received_utc=$receivedUtc }
}

function Get-IncomingManifestPath([string]$TransferId) {
    if (-not (Test-GuidText $TransferId)) { throw 'Transfer ID is invalid.' }
    return (Join-Path $script:Paths.Incoming ($TransferId.ToLowerInvariant() + '.json'))
}
function Get-IncomingDataPath([string]$TransferId) {
    if (-not (Test-GuidText $TransferId)) { throw 'Transfer ID is invalid.' }
    return (Join-Path $script:Paths.IncomingData ($TransferId.ToLowerInvariant() + '.part'))
}
function Get-FileReceiptPath([string]$TransferId) {
    if (-not (Test-GuidText $TransferId)) { throw 'Transfer ID is invalid.' }
    return (Join-Path $script:Paths.Sent ('received-file-' + $TransferId.ToLowerInvariant() + '.json'))
}

function Receive-FileBegin {
    param($Peer,$Payload)
    $tid = [string]$Payload.transfer_id
    if (-not (Test-GuidText $tid)) { throw 'Transfer ID is invalid.' }
    [long]$size = 0
    if (-not [long]::TryParse([string]$Payload.size,[ref]$size) -or $size -lt 0 -or $size -gt $script:MaxTransferBytes) { throw 'File size is invalid or exceeds the 10 GiB safety limit.' }
    $hash = ([string]$Payload.sha256).ToLowerInvariant()
    if ($hash -notmatch '^[0-9a-f]{64}$') { throw 'File SHA-256 is invalid.' }
    $receiptPath = Get-FileReceiptPath $tid
    if (Test-Path -LiteralPath $receiptPath) {
        $receipt = Read-JsonFile $receiptPath
        if ($receipt.from_peer_id -ne $Peer.peer_id -or [long]$receipt.size -ne $size -or -not [string]::Equals([string]$receipt.sha256,$hash,[StringComparison]::OrdinalIgnoreCase)) { throw 'Existing file receipt conflicts with this peer or metadata.' }
        return [ordered]@{ ok=$true; status='complete'; transfer_id=$tid; current_offset=$size; final_name=$receipt.final_name }
    }
    $manifestPath = Get-IncomingManifestPath $tid
    $partPath = Get-IncomingDataPath $tid
    if (Test-Path -LiteralPath $manifestPath) {
        $m = Read-JsonFile $manifestPath
        if ($m.from_peer_id -ne $Peer.peer_id -or [long]$m.size -ne $size -or $m.sha256 -ne $hash) { throw 'Transfer metadata conflicts with an existing partial transfer.' }
        $partPath = Resolve-IncomingStoredPath -Manifest $m -Kind Part
        $resolvedFinal = Resolve-IncomingStoredPath -Manifest $m -Kind Final
        if (Test-Path -LiteralPath $resolvedFinal) {
            $finalItem = Get-Item -LiteralPath $resolvedFinal
            $finalHash = if ($finalItem.Length -eq $size) { Get-Sha256HexFromFile $resolvedFinal } else { '' }
            if ($finalItem.Length -eq $size -and [string]::Equals($finalHash,$hash,[StringComparison]::OrdinalIgnoreCase)) {
                $repairReceipt = [ordered]@{ schema='lanlink-received-file-receipt-v2'; transfer_id=$tid; from_peer_id=[string]$Peer.peer_id; final_name=[string]$m.final_name; final_path=$resolvedFinal; size=$size; sha256=$hash; completed_utc=Get-UtcIso; recovered_after_rename=$true }
                Write-JsonFile -Path $receiptPath -Object $repairReceipt
                Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $partPath -Force -ErrorAction SilentlyContinue
                return [ordered]@{ ok=$true; status='complete'; transfer_id=$tid; current_offset=$size; final_name=[string]$m.final_name }
            }
            throw 'Final destination exists but does not match the transfer receipt data.'
        }
    } else {
        $safe = Get-SafeLeafName ([string]$Payload.name)
        $peerDir = Join-Path $script:Paths.InboxFiles (Get-PeerSafeFolderName $Peer)
        if (-not (Test-Path -LiteralPath $peerDir)) { [void](New-Item -ItemType Directory -Path $peerDir -Force) }
        $base = [IO.Path]::GetFileNameWithoutExtension($safe)
        $ext = [IO.Path]::GetExtension($safe)
        $finalName = $base + '__' + $tid.Substring(0,8) + $ext
        $finalPath = Join-Path $peerDir $finalName
        $m = [ordered]@{
            schema          = 'lanlink-incoming-file-v2'
            transfer_id     = $tid
            from_peer_id    = [string]$Peer.peer_id
            from_name       = [string]$Peer.display_name
            original_name   = $safe
            size            = $size
            sha256          = $hash
            part_path       = $partPath
            final_path      = $finalPath
            part_rel_path   = Get-ProjectRelativePath $partPath
            final_rel_path  = Get-ProjectRelativePath $finalPath
            final_name      = $finalName
            received_bytes  = 0
            created_utc     = Get-UtcIso
            updated_utc     = Get-UtcIso
        }
        $cfg = Get-AppConfig
        [void](Assert-IncomingCapacity -Path $partPath -AdditionalBytes $size -Config $cfg)
        Write-JsonFile -Path $manifestPath -Object $m
    }
    [long]$actual = 0
    if (Test-Path -LiteralPath $partPath) { $actual = (Get-Item -LiteralPath $partPath).Length }
    if ($actual -gt $size) { throw 'Partial file is larger than the declared file size.' }
    $cfg = Get-AppConfig
    [void](Assert-IncomingCapacity -Path $partPath -AdditionalBytes ($size - $actual) -Config $cfg)
    $m.received_bytes = $actual
    $m.updated_utc = Get-UtcIso
    Write-JsonFile -Path $manifestPath -Object $m
    return [ordered]@{ ok=$true; status='ready'; transfer_id=$tid; current_offset=$actual; final_name=[string]$m.final_name }
}

function Receive-FileChunk {
    param($Peer,$Payload)
    $tid = [string]$Payload.transfer_id
    $manifestPath = Get-IncomingManifestPath $tid
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'No matching partial transfer exists. Restart with file.begin.' }
    $m = Read-JsonFile $manifestPath
    if ($m.from_peer_id -ne $Peer.peer_id) { throw 'Transfer belongs to another peer.' }
    [long]$offset = 0
    if (-not [long]::TryParse([string]$Payload.offset,[ref]$offset) -or $offset -lt 0) { throw 'Chunk offset is invalid.' }
    $data = [Convert]::FromBase64String([string]$Payload.data_b64)
    $cfg = Get-AppConfig
    if ($data.Length -lt 1 -or $data.Length -gt [int]$cfg.file_chunk_bytes) { throw 'Chunk size is invalid.' }
    $chunkHash = Get-Sha256HexFromBytes $data
    if (-not [string]::Equals($chunkHash,[string]$Payload.chunk_sha256,[StringComparison]::OrdinalIgnoreCase)) { throw 'Chunk SHA-256 verification failed.' }
    $partPath = Resolve-IncomingStoredPath -Manifest $m -Kind Part
    [long]$current = 0
    if (Test-Path -LiteralPath $partPath) { $current = (Get-Item -LiteralPath $partPath).Length }
    if ($offset -gt $current) { throw "Chunk arrived out of order. Expected offset $current." }
    if ($offset -lt $current) {
        if (($offset + $data.Length) -gt $current) { throw 'Chunk overlaps the durable file boundary.' }
        $existing = New-Object byte[] $data.Length
        $rfs = [IO.File]::Open($partPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            [void]$rfs.Seek($offset,[IO.SeekOrigin]::Begin)
            $got = 0
            while ($got -lt $existing.Length) {
                $n = $rfs.Read($existing,$got,$existing.Length-$got)
                if ($n -le 0) { throw 'Could not verify a duplicate chunk.' }
                $got += $n
            }
        } finally { $rfs.Dispose() }
        if (-not [string]::Equals((Get-Sha256HexFromBytes $existing),$chunkHash,[StringComparison]::OrdinalIgnoreCase)) { throw 'Duplicate chunk conflicts with durable data.' }
        return [ordered]@{ ok=$true; status='duplicate'; transfer_id=$tid; next_offset=$current }
    }
    if (($current + $data.Length) -gt [long]$m.size) { throw 'Chunk would exceed the declared file size.' }
    [void](Assert-IncomingCapacity -Path $partPath -AdditionalBytes $data.Length -Config $cfg)
    $fs = [IO.FileStream]::new($partPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::Write,[IO.FileShare]::Read,65536,[IO.FileOptions]::WriteThrough)
    try {
        [void]$fs.Seek($current,[IO.SeekOrigin]::Begin)
        $fs.Write($data,0,$data.Length)
        $fs.Flush($true)
    } finally { $fs.Dispose() }
    $current += $data.Length
    $m.received_bytes = $current
    $m.updated_utc = Get-UtcIso
    Write-JsonFile -Path $manifestPath -Object $m
    return [ordered]@{ ok=$true; status='accepted'; transfer_id=$tid; next_offset=$current }
}

function Receive-FileFinish {
    param($Peer,$Payload)
    $tid = [string]$Payload.transfer_id
    $receiptPath = Get-FileReceiptPath $tid
    if (Test-Path -LiteralPath $receiptPath) {
        $r = Read-JsonFile $receiptPath
        if ($r.from_peer_id -ne $Peer.peer_id) { throw 'Existing file receipt belongs to another peer.' }
        return [ordered]@{ ok=$true; status='complete'; transfer_id=$tid; final_name=$r.final_name; sha256=$r.sha256 }
    }
    $manifestPath = Get-IncomingManifestPath $tid
    if (-not (Test-Path -LiteralPath $manifestPath)) { throw 'Partial transfer manifest is missing.' }
    $m = Read-JsonFile $manifestPath
    if ($m.from_peer_id -ne $Peer.peer_id) { throw 'Transfer belongs to another peer.' }
    $partPath = Resolve-IncomingStoredPath -Manifest $m -Kind Part
    $resolvedFinal = Resolve-IncomingStoredPath -Manifest $m -Kind Final
    if (-not (Test-Path -LiteralPath $partPath)) {
        if (Test-Path -LiteralPath $resolvedFinal) {
            $finalLength = (Get-Item -LiteralPath $resolvedFinal).Length
            $finalHash = if ($finalLength -eq [long]$m.size) { Get-Sha256HexFromFile $resolvedFinal } else { '' }
            if ($finalLength -eq [long]$m.size -and [string]::Equals($finalHash,[string]$m.sha256,[StringComparison]::OrdinalIgnoreCase)) {
                $repair = [ordered]@{ schema='lanlink-received-file-receipt-v2'; transfer_id=$tid; from_peer_id=[string]$Peer.peer_id; final_name=[string]$m.final_name; final_path=$resolvedFinal; size=[long]$m.size; sha256=$finalHash; completed_utc=Get-UtcIso; recovered_after_rename=$true }
                Write-JsonFile -Path $receiptPath -Object $repair
                Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
                return [ordered]@{ ok=$true; status='complete'; transfer_id=$tid; final_name=[string]$m.final_name; sha256=$finalHash }
            }
            throw 'Final file exists but failed recovery verification.'
        }
        if ([long]$m.size -eq 0) {
            $empty = [IO.File]::Open($partPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $empty.Flush($true) } finally { $empty.Dispose() }
        } else { throw 'Partial file data is missing.' }
    }
    $length = (Get-Item -LiteralPath $partPath).Length
    if ($length -ne [long]$m.size) { throw "File is incomplete: $length of $($m.size) bytes." }
    $actualHash = Get-Sha256HexFromFile $partPath
    if (-not [string]::Equals($actualHash,[string]$m.sha256,[StringComparison]::OrdinalIgnoreCase)) { throw 'Final file SHA-256 verification failed. The partial file was retained for diagnosis.' }
    $finalPath = $resolvedFinal
    $finalDir = Split-Path -Parent $finalPath
    if (-not (Test-Path -LiteralPath $finalDir)) { [void](New-Item -ItemType Directory -Path $finalDir -Force) }
    if (Test-Path -LiteralPath $finalPath) {
        $existingHash = Get-Sha256HexFromFile $finalPath
        if (-not [string]::Equals($existingHash,$actualHash,[StringComparison]::OrdinalIgnoreCase)) { throw 'Final destination already contains different data.' }
        Remove-Item -LiteralPath $partPath -Force
    } else {
        [IO.File]::Move($partPath,$finalPath)
    }
    $receipt = [ordered]@{
        schema       = 'lanlink-received-file-receipt-v2'
        transfer_id  = $tid
        from_peer_id = [string]$Peer.peer_id
        final_name   = [string]$m.final_name
        final_path   = $finalPath
        size         = [long]$m.size
        sha256       = $actualHash
        completed_utc= Get-UtcIso
    }
    Write-JsonFile -Path $receiptPath -Object $receipt
    Remove-Item -LiteralPath $manifestPath -Force -ErrorAction SilentlyContinue
    Write-Host ''
    Write-Host ('FILE received from {0}: {1}' -f $Peer.display_name, $m.final_name) -ForegroundColor Cyan
    return [ordered]@{ ok=$true; status='complete'; transfer_id=$tid; final_name=[string]$m.final_name; sha256=$actualHash }
}

function Handle-PairRequest {
    param($Envelope,[string]$RemoteAddress,[string]$LocalAddress)
    $untrusted = Read-UntrustedEnvelopePayload $Envelope
    $inviteId = [string]$untrusted.invite_id
    $statePath = Get-InviteStatePath $inviteId
    if (-not (Test-Path -LiteralPath $statePath)) { throw 'Pairing invitation is unknown.' }
    $state = Read-JsonFile $statePath
    $inviteSecret = Unprotect-Base64ToBytes ([string]$state.secret_protected)
    $payload = Assert-EnvelopeAuth -Envelope $Envelope -Secret $inviteSecret
    if ($payload.peer_id -ne $Envelope.sender_peer_id) { throw 'Pairing sender ID mismatch.' }
    $expiry = ConvertTo-UtcDateTime ([string]$state.expires_utc)
    if ([DateTime]::UtcNow -gt $expiry) { throw 'Pairing invitation expired.' }
    if (-not (Test-PrivateIPv4 $RemoteAddress)) { throw 'Pairing request did not originate from a private IPv4 address.' }
    if (-not (Test-GuidText ([string]$payload.peer_id)) -or [string]$payload.display_name -eq '') { throw 'Pairing identity is invalid.' }
    if ([int]$payload.listen_port -lt 1 -or [int]$payload.listen_port -gt 65535) { throw 'Pairing listen port is invalid.' }
    if (-not (Test-PrivateIPv4 ([string]$payload.listen_ip))) { throw 'Pairing listen address is not private.' }
    $peerDer = [Convert]::FromBase64String([string]$payload.cert_der_b64)
    $peerCertInfo = Get-CertificateInfoFromDer -DerBytes $peerDer -ExpectedFingerprint ([string]$payload.cert_sha256) -ExpectedPeerId ([string]$payload.peer_id)
    $peerFp = [string]$peerCertInfo.fingerprint
    $shared = $null
    if ($state.used_by_peer_id) {
        if (-not [string]::Equals([string]$state.used_by_peer_id,[string]$payload.peer_id,[StringComparison]::OrdinalIgnoreCase)) { throw 'Pairing invitation was already used by another PC.' }
        $existingPeer = Get-Peer ([string]$payload.peer_id) -AllowDisabled
        if (-not [string]::Equals([string]$existingPeer.cert_sha256,$peerFp,[StringComparison]::OrdinalIgnoreCase)) { throw 'A reused invitation presented a different peer certificate.' }
        if ($existingPeer.enabled -eq $false) { throw 'This peer was disabled; create a fresh invitation to pair it again intentionally.' }
        $shared = Unprotect-Base64ToBytes ([string]$state.shared_secret_protected)
    } else {
        $shared = New-RandomBytes 32
        $peer = [ordered]@{
            schema                    = 'lanlink-peer-v2'
            peer_id                   = [string]$payload.peer_id
            display_name              = ([string]$payload.display_name).Substring(0,[Math]::Min(80,([string]$payload.display_name).Length))
            machine_name              = ([string]$payload.machine_name).Substring(0,[Math]::Min(255,([string]$payload.machine_name).Length))
            endpoint_ip               = $RemoteAddress
            claimed_ip                = [string]$payload.listen_ip
            last_success_ip           = $RemoteAddress
            port                      = [int]$payload.listen_port
            cert_sha256               = $peerFp
            cert_der_b64              = [string]$payload.cert_der_b64
            cert_not_after_utc         = [string]$peerCertInfo.not_after_utc
            shared_secret_protected   = Protect-BytesToBase64 $shared
            paired_utc                = Get-UtcIso
            last_seen_utc             = Get-UtcIso
            enabled                   = $true
            capabilities              = @($payload.capabilities)
        }
        Save-Peer $peer
        $state.used_by_peer_id = [string]$payload.peer_id
        $state.shared_secret_protected = Protect-BytesToBase64 $shared
        $state.paired_utc = Get-UtcIso
        Write-JsonFile -Path $statePath -Object $state
        if ($state.export_rel_path) { try { Remove-Item -LiteralPath (Resolve-ProjectRelativePath ([string]$state.export_rel_path)) -Force -ErrorAction SilentlyContinue } catch { } }
        Write-Info "Paired with $($peer.display_name) from $RemoteAddress."
    }
    $identity = Get-LocalIdentity
    $cert = Get-IdentityCertificate
    try { $certDer = [Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)) }
    finally { $cert.Dispose() }
    $cfg = Get-AppConfig
    $replyPayload = [ordered]@{
        ok                 = $true
        display_name       = [string]$identity.display_name
        machine_name       = [string]$identity.machine_name
        listen_ip          = $LocalAddress
        listen_port        = [int]$cfg.listen_port
        cert_sha256        = [string]$identity.cert_sha256
        cert_der_b64       = $certDer
        shared_secret_b64  = [Convert]::ToBase64String($shared)
        capabilities       = @($script:Capabilities)
        paired_utc         = Get-UtcIso
    }
    return [pscustomobject]@{ Secret=$inviteSecret; Payload=$replyPayload }
}

function Invoke-AuthenticatedOperation {
    param($Peer,[string]$Operation,$Payload)
    switch ($Operation) {
        'ping' {
            return [ordered]@{ ok=$true; status='online'; server_utc=Get-UtcIso; version=$script:Version; capabilities=@($script:Capabilities) }
        }
        'message.send' { return Receive-TextMessage -Peer $Peer -Payload $Payload }
        'file.begin'   { return Receive-FileBegin -Peer $Peer -Payload $Payload }
        'file.chunk'   { return Receive-FileChunk -Peer $Peer -Payload $Payload }
        'file.finish'  { return Receive-FileFinish -Peer $Peer -Payload $Payload }
        default { throw 'Unsupported operation.' }
    }
}

function Handle-TlsClient {
    param([Net.Sockets.TcpClient]$TcpClient,[Security.Cryptography.X509Certificates.X509Certificate2]$ServerCertificate)
    $remote = [string]$TcpClient.Client.RemoteEndPoint.Address.IPAddressToString
    $local = [string]$TcpClient.Client.LocalEndPoint.Address.IPAddressToString
    if (-not (Test-PrivateIPv4 $remote)) { throw 'Rejected a connection from outside the private IPv4 ranges.' }
    $cfg = Get-AppConfig
    $TcpClient.NoDelay = $true
    $TcpClient.ReceiveTimeout = [int]$cfg.io_timeout_ms
    $TcpClient.SendTimeout = [int]$cfg.io_timeout_ms
    $keepAliveApplied = Set-TcpKeepAlive -TcpClient $TcpClient -Config $cfg
    $ssl = [Net.Security.SslStream]::new($TcpClient.GetStream(),$false)
    try {
        $ssl.ReadTimeout = [int]$cfg.io_timeout_ms
        $ssl.WriteTimeout = [int]$cfg.io_timeout_ms
        $ssl.AuthenticateAsServer($ServerCertificate,$false,$script:TlsProtocols,$false)
        if (-not (Test-AcceptableTlsProtocol $ssl.SslProtocol)) { throw ('Negotiated TLS protocol is below the TLS 1.2 minimum: ' + [string]$ssl.SslProtocol) }
        $tlsLabel = Get-TlsProtocolLabel $ssl.SslProtocol
        Write-AppLog -Level INFO -Message "Accepted TLS session protocol=$tlsLabel keepalive=$keepAliveApplied remote=$remote."
        $sessionClock = [Diagnostics.Stopwatch]::StartNew()
        [int]$requestCount = 0
        while ($true) {
            if ($requestCount -ge [int]$cfg.max_session_requests) {
                Write-AppLog -Level WARN -Message "Session request quota reached remote=$remote requests=$requestCount. Client can reconnect and resume safely."
                break
            }
            if ($sessionClock.Elapsed.TotalSeconds -ge [int]$cfg.max_session_seconds) {
                Write-AppLog -Level WARN -Message "Session duration quota reached remote=$remote seconds=$([int]$sessionClock.Elapsed.TotalSeconds). Client can reconnect and resume safely."
                break
            }
            try { $envelope = Read-Frame -Stream $ssl } catch {
                if ($_.Exception.Message -match 'closed before|Unable to read|forcibly closed|timed out') { break }
                throw
            }
            $requestCount++
            $operation = [string]$envelope.operation
            if ($operation -eq 'pair.request') {
                $pair = Handle-PairRequest -Envelope $envelope -RemoteAddress $remote -LocalAddress $local
                $identity = Get-LocalIdentity
                $response = New-AuthEnvelope -Operation 'pair.response' -SenderPeerId ([string]$identity.peer_id) -Payload $pair.Payload -Secret $pair.Secret -CorrelationId ([string]$envelope.request_id)
                Write-Frame -Stream $ssl -Object $response
                continue
            }
            $senderId = [string]$envelope.sender_peer_id
            $peer = Get-Peer $senderId
            $secret = Get-PeerSecret $peer
            $payload = Assert-EnvelopeAuth -Envelope $envelope -Secret $secret -ExpectedSenderPeerId $senderId
            $replay = Test-ReplaySeen $senderId ([string]$envelope.request_id)
            if ($replay) { throw 'Duplicate request envelope rejected. Retry with a fresh request ID.' }
            try {
                $result = Invoke-AuthenticatedOperation -Peer $peer -Operation $operation -Payload $payload
            } catch {
                $result = [ordered]@{ ok=$false; message=$_.Exception.Message; error_code='operation_failed' }
            }
            Mark-ReplaySeen $senderId ([string]$envelope.request_id) $operation
            [void](Update-PeerActivity -PeerId $senderId -SuccessfulIp $remote)
            $identity = Get-LocalIdentity
            $response = New-AuthEnvelope -Operation ('response.'+$operation) -SenderPeerId ([string]$identity.peer_id) -Payload $result -Secret $secret -CorrelationId ([string]$envelope.request_id)
            Write-Frame -Stream $ssl -Object $response
        }
    } finally { $ssl.Dispose() }
}


function Get-SelectedListenAddress {
    param([switch]$Interactive)
    $cfg = Get-AppConfig
    $ips = @(Get-LocalPrivateIPv4s)
    if (-not $ips.Count) { throw 'No RFC1918 private IPv4 address was found.' }
    if ($cfg.preferred_ip -and $cfg.preferred_ip -in $ips) { return [string]$cfg.preferred_ip }
    if ($Interactive) { return Select-LocalPrivateIPv4 }
    if ($ips.Count -eq 1) { $cfg.preferred_ip = [string]$ips[0]; Save-AppConfig $cfg; return [string]$ips[0] }
    throw 'Multiple private IPv4 adapters are active and no preferred IP is set. Create a pairing invitation or start the receiver from the main menu once to choose the router-facing address.'
}

function Get-NetworkCategoryForAddress([string]$Address) {
    try {
        $ip = Get-NetIPAddress -IPAddress $Address -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1
        $profile = Get-NetConnectionProfile -InterfaceIndex $ip.InterfaceIndex -ErrorAction Stop | Select-Object -First 1
        return [string]$profile.NetworkCategory
    } catch { return 'Unknown' }
}

function Enter-ReceiverMutex([string]$Address,[int]$Port) {
    try { return Enter-ProjectMutex -Purpose ("Receiver-$Address-$Port") -TimeoutMs 0 }
    catch { throw "Another receiver already owns $Address`:$Port for this project." }
}

function Start-Receiver {
    param([int]$ListenPort,[switch]$InteractiveAddress)
    $identity = Get-LocalIdentity
    $bindIp = Get-SelectedListenAddress -Interactive:$InteractiveAddress
    $category = Get-NetworkCategoryForAddress $bindIp
    if ($category -eq 'Public') { throw "The selected adapter ($bindIp) is Public. Change it to Private in Windows before starting the receiver." }
    if ($category -eq 'Unknown') { Write-Warn 'The selected adapter network category could not be confirmed. The firewall rule still remains Private + LocalSubnet only.' }
    $mutex = Enter-ReceiverMutex -Address $bindIp -Port $ListenPort
    $cert = Get-IdentityCertificate
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($bindIp),$ListenPort)
    try {
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start(20)
        Clear-Host
        Write-Host "LAN Router Comms v$script:Version receiver" -ForegroundColor Cyan
        Write-Host ('PC: {0}' -f $identity.display_name)
        Write-Host ('Listening: {0}:{1} ({2} profile)' -f $bindIp,$ListenPort,$category)
        Write-Host 'Security: pinned TLS + per-peer HMAC; private IPv4 only'
        Write-Host 'Press Ctrl+C to stop. This is a visible foreground receiver.'
        Write-Host ''
        Write-AppLog -Level INFO -Message "Receiver ready on $bindIp`:$ListenPort profile=$category."
        while ($true) {
            $client = $listener.AcceptTcpClient()
            try { Handle-TlsClient -TcpClient $client -ServerCertificate $cert }
            catch { Write-Warn ('Connection rejected or failed: ' + $_.Exception.Message) }
            finally { $client.Close() }
        }
    } finally {
        try { $listener.Stop() } catch { }
        $cert.Dispose()
        try { $mutex.ReleaseMutex() } catch { }
        $mutex.Dispose()
        Write-AppLog -Level INFO -Message 'Receiver stopped.'
    }
}


function Start-ReceiverWindow {
    param([int]$Port)
    [void](Select-LocalPrivateIPv4)
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args = '-NoLogo -NoProfile -File "{0}" -Mode Receiver -Port {1}' -f $script:ScriptPath.Replace('"','\"'),$Port
    [void](Start-Process -FilePath $ps -ArgumentList $args -WorkingDirectory $script:Root)
    Write-Info 'Opened the receiver in a separate visible window.'
}

function Queue-TextMessage {
    param($Peer,[string]$Text)
    $cfg = Get-AppConfig
    $len = $script:Utf8NoBom.GetByteCount($Text)
    if ($len -lt 1 -or $len -gt [int]$cfg.max_message_bytes) { throw "Message must be 1 to $($cfg.max_message_bytes) UTF-8 bytes." }
    if (@(Get-ChildItem -LiteralPath $script:Paths.OutboxMessages -Filter '*.json' -File -ErrorAction SilentlyContinue).Count -ge [int]$cfg.max_pending_messages) { throw 'Message queue is full. Deliver or inspect pending messages before adding more.' }
    $id = [guid]::NewGuid().ToString('D')
    $item = [ordered]@{
        schema          = 'lanlink-outbox-message-v2'
        message_id      = $id
        peer_id         = [string]$Peer.peer_id
        created_utc     = Get-UtcIso
        sent_utc        = Get-UtcIso
        text_protected  = Protect-TextToBase64 $Text
        attempts        = 0
        last_error      = ''
        next_attempt_utc= Get-UtcIso
    }
    $path = Join-Path $script:Paths.OutboxMessages ($id + '.json')
    Write-JsonFile -Path $path -Object $item
    return $path
}

function Deliver-QueuedMessage {
    param([string]$QueuePath)
    $queueMutex = Enter-ProjectMutex -Purpose ('MessageQueueItem_' + [IO.Path]::GetFileNameWithoutExtension($QueuePath)) -TimeoutMs 2000
    try {
        if (-not (Test-Path -LiteralPath $QueuePath -PathType Leaf)) { Write-Info 'Message queue item was already completed or removed.'; return $true }
    $item = Read-JsonFile $QueuePath
    $peer = Get-Peer ([string]$item.peer_id)
    $text = Unprotect-Base64ToText ([string]$item.text_protected)
    $payload = [ordered]@{ message_id=[string]$item.message_id; sent_utc=[string]$item.sent_utc; text=$text; format='text/plain; charset=utf-8' }
    try {
        $reply = Invoke-PeerRequest -Peer $peer -Operation 'message.send' -Payload $payload
        $receipt = [ordered]@{
            schema        = 'lanlink-sent-message-receipt-v2'
            message_id    = [string]$item.message_id
            peer_id       = [string]$peer.peer_id
            peer_name     = [string]$peer.display_name
            delivered_utc = [string]$reply.received_utc
            duplicate     = [bool]$reply.duplicate
        }
        $receiptPath = Join-Path $script:Paths.Sent ('message-' + $item.message_id + '.json')
        Write-JsonFile -Path $receiptPath -Object $receipt
        Remove-Item -LiteralPath $QueuePath -Force
        Write-Info "Delivered message to $($peer.display_name)."
        return $true
    } catch {
        $item.attempts = [int]$item.attempts + 1
        $item.last_error = $_.Exception.Message
        $cfg = Get-AppConfig
        $delay = Get-RetryDelaySeconds -Attempts ([int]$item.attempts) -Config $cfg
        $item.next_attempt_utc = [DateTime]::UtcNow.AddSeconds($delay).ToString('o')
        Write-JsonFile -Path $QueuePath -Object $item
        Write-Warn "Message remains safely queued: $($_.Exception.Message)"
        return $false
    }
    } finally { Exit-ProjectMutex $queueMutex }
}

function Send-TextMessageInteractive {
    $peer = Select-Peer
    Write-Host 'Type the message. Press Enter to send.'
    $text = Read-Host 'Message'
    $path = Queue-TextMessage -Peer $peer -Text $text
    [void](Deliver-QueuedMessage $path)
}


function Queue-FileTransfer {
    param($Peer,[string]$SourcePath)
    $full = [IO.Path]::GetFullPath($SourcePath)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'Source file was not found.' }
    $cfg = Get-AppConfig
    if (@(Get-ChildItem -LiteralPath $script:Paths.OutboxFiles -Filter '*.json' -File -ErrorAction SilentlyContinue).Count -ge [int]$cfg.max_pending_files) { throw 'File queue is full. Deliver or inspect pending files before adding more.' }
    $file = Get-Item -LiteralPath $full
    if ($file.Length -gt $script:MaxTransferBytes) { throw 'Files larger than 10 GiB are outside the safety limit.' }
    $id = [guid]::NewGuid().ToString('D')
    Write-Info "Hashing $($file.Name) before transfer..."
    $hash = Get-Sha256HexFromFile $full
    $rel = Get-ProjectRelativePath $full
    $item = [ordered]@{
        schema               = 'lanlink-outbox-file-v2.1'
        transfer_id          = $id
        peer_id              = [string]$Peer.peer_id
        source_path_kind     = if ($rel) { 'project-relative' } else { 'external-absolute' }
        source_rel_path      = $rel
        source_path          = if ($rel) { '' } else { $full }
        source_name          = [string]$file.Name
        source_size          = [long]$file.Length
        source_lastwrite_utc = $file.LastWriteTimeUtc.ToString('o')
        sha256               = $hash
        last_acked_offset    = 0
        created_utc          = Get-UtcIso
        attempts             = 0
        last_error           = ''
        next_attempt_utc     = Get-UtcIso
    }
    $path = Join-Path $script:Paths.OutboxFiles ($id + '.json')
    Write-JsonFile -Path $path -Object $item
    return $path
}

function Invoke-FileQueueItem {
    param([string]$QueuePath)
    $queueMutex = Enter-ProjectMutex -Purpose ('FileQueueItem_' + [IO.Path]::GetFileNameWithoutExtension($QueuePath)) -TimeoutMs 2000
    try {
        if (-not (Test-Path -LiteralPath $QueuePath -PathType Leaf)) { Write-Info 'File queue item was already completed or removed.'; return $true }
    $item = Read-JsonFile $QueuePath
    $peer = Get-Peer ([string]$item.peer_id)
    $resolvedSource = Resolve-QueuedSourcePath $item
    if (-not (Test-Path -LiteralPath $resolvedSource -PathType Leaf)) { throw 'Queued source file is no longer present. If the project moved, inspect the queue portability status in diagnostics.' }
    $file = Get-Item -LiteralPath $resolvedSource
    if ($file.Length -ne [long]$item.source_size -or $file.LastWriteTimeUtc.ToString('o') -ne [string]$item.source_lastwrite_utc) {
        throw 'Queued source file changed after it was hashed. Queue a new transfer to fail closed.'
    }
    $secret = Get-PeerSecret $peer
    $addresses = @(Get-PeerEndpointCandidates $peer)
    $session = $null
    try {
        $session = Open-TlsPinnedSession -Addresses $addresses -Port ([int]$peer.port) -ExpectedFingerprint ([string]$peer.cert_sha256) -ExpectedPeerId ([string]$peer.peer_id)
        $begin = Invoke-SessionRequest -Session $session -Peer $peer -Secret $secret -Operation 'file.begin' -Payload ([ordered]@{
            transfer_id=[string]$item.transfer_id; name=[string]$item.source_name; size=[long]$item.source_size; sha256=[string]$item.sha256; modified_utc=[string]$item.source_lastwrite_utc
        })
        [long]$offset = [long]$begin.current_offset
        if ($offset -lt 0 -or $offset -gt [long]$item.source_size) { throw 'Peer returned an invalid resume offset.' }
        $cfg = Get-AppConfig
        $chunkSize = [int]$cfg.file_chunk_bytes
        $fs = [IO.File]::Open($resolvedSource,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            [void]$fs.Seek($offset,[IO.SeekOrigin]::Begin)
            $buffer = New-Object byte[] $chunkSize
            while ($offset -lt [long]$item.source_size) {
                $remaining = [long]$item.source_size - $offset
                $want = [int][Math]::Min([long]$buffer.Length,$remaining)
                $read = 0
                while ($read -lt $want) {
                    $n = $fs.Read($buffer,$read,$want-$read)
                    if ($n -le 0) { throw 'Source file ended unexpectedly.' }
                    $read += $n
                }
                if ($read -eq $buffer.Length) { $chunk = $buffer }
                else { $chunk = New-Object byte[] $read; [Array]::Copy($buffer,$chunk,$read) }
                $reply = Invoke-SessionRequest -Session $session -Peer $peer -Secret $secret -Operation 'file.chunk' -Payload ([ordered]@{
                    transfer_id=[string]$item.transfer_id; offset=$offset; data_b64=[Convert]::ToBase64String($chunk); chunk_sha256=Get-Sha256HexFromBytes $chunk
                })
                [long]$next = [long]$reply.next_offset
                if ($next -ne ($offset + $read)) { throw 'Peer returned a non-exact chunk acknowledgment. Resume is renegotiated safely on the next connection.' }
                $offset = $next
                $item.last_acked_offset = $offset
                $item.last_error = ''
                Write-JsonFile -Path $QueuePath -Object $item
                $pct = if ([long]$item.source_size -eq 0) { 100 } else { [int](($offset*100.0)/[long]$item.source_size) }
                Write-Progress -Activity ('Sending ' + $item.source_name) -Status "$offset of $($item.source_size) bytes" -PercentComplete $pct
            }
        } finally { $fs.Dispose(); Write-Progress -Activity ('Sending ' + $item.source_name) -Completed }
        $finish = Invoke-SessionRequest -Session $session -Peer $peer -Secret $secret -Operation 'file.finish' -Payload ([ordered]@{ transfer_id=[string]$item.transfer_id })
        if (-not [string]::Equals([string]$finish.sha256,[string]$item.sha256,[StringComparison]::OrdinalIgnoreCase)) { throw 'Peer completion receipt hash does not match.' }
        $receipt = [ordered]@{
            schema='lanlink-sent-file-receipt-v2'; transfer_id=[string]$item.transfer_id; peer_id=[string]$peer.peer_id; peer_name=[string]$peer.display_name;
            source_name=[string]$item.source_name; size=[long]$item.source_size; sha256=[string]$item.sha256; remote_name=[string]$finish.final_name; delivered_utc=Get-UtcIso
        }
        Write-JsonFile -Path (Join-Path $script:Paths.Sent ('file-' + $item.transfer_id + '.json')) -Object $receipt
        try { [void](Update-PeerActivity -PeerId ([string]$peer.peer_id) -SuccessfulIp ([string]$session.Address)) } catch { Write-AppLog -Level WARN -Message ('File delivered but peer last-seen update failed: ' + $_.Exception.Message) }
        Remove-Item -LiteralPath $QueuePath -Force
        Write-Info "Delivered file to $($peer.display_name): $($finish.final_name)"
        return $true
    } catch {
        if (-not (Test-Path -LiteralPath $QueuePath)) { Write-Warn ('Transfer may have completed, but post-delivery bookkeeping failed: ' + $_.Exception.Message); return $false }
        $item = Read-JsonFile $QueuePath
        $item.attempts = [int]$item.attempts + 1
        $item.last_error = $_.Exception.Message
        $cfg = Get-AppConfig
        $delay = Get-RetryDelaySeconds -Attempts ([int]$item.attempts) -Config $cfg
        $item.next_attempt_utc = [DateTime]::UtcNow.AddSeconds($delay).ToString('o')
        Write-JsonFile -Path $QueuePath -Object $item
        Write-Warn "File remains resumably queued: $($_.Exception.Message)"
        return $false
    } finally { Close-TlsSession $session }
    } finally { Exit-ProjectMutex $queueMutex }
}

function Send-FileInteractive {
    $peer = Select-Peer
    $path = (Read-Host 'Full path to the file').Trim('"')
    $queue = Queue-FileTransfer -Peer $peer -SourcePath $path
    [void](Invoke-FileQueueItem $queue)
}

function Retry-PendingQueue {
    param(
        [switch]$Force,
        [switch]$StartupSweep
    )
    $messages = @(Get-ChildItem -LiteralPath $script:Paths.OutboxMessages -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)
    $files = @(Get-ChildItem -LiteralPath $script:Paths.OutboxFiles -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc)
    if ($messages.Count + $files.Count -eq 0) {
        if (-not $StartupSweep) { Write-Info 'The delivery queue is empty.' }
        return
    }

    # Normal/manual retry processes the full queue. The launch sweep is deliberately
    # bounded to one due text message and never starts a potentially large file transfer.
    # This gives small offline messages a recovery opportunity without making menu startup
    # feel like a background service or an unbounded network operation.
    if ($StartupSweep) {
        foreach ($f in $messages) {
            try {
                $i = Read-JsonFile $f.FullName
                $due = ConvertTo-UtcDateTime ([string]$i.next_attempt_utc)
                if ($due -le [DateTime]::UtcNow) {
                    Write-AppLog -Level INFO -Message ("Foreground startup sweep retrying one due message item=" + $f.Name)
                    [void](Deliver-QueuedMessage $f.FullName)
                    break
                }
            } catch {
                Write-AppLog -Level WARN -Message ("Startup sweep skipped message queue item " + $f.Name + ': ' + $_.Exception.Message)
                break
            }
        }
        return
    }

    Write-Info "Retrying $($messages.Count) message(s) and $($files.Count) file(s)."
    foreach ($f in $messages) {
        try {
            $i = Read-JsonFile $f.FullName
            $due = ConvertTo-UtcDateTime ([string]$i.next_attempt_utc)
            if ($Force -or $due -le [DateTime]::UtcNow) { [void](Deliver-QueuedMessage $f.FullName) }
        } catch { Write-Warn "Skipped message queue item $($f.Name): $($_.Exception.Message)" }
    }
    foreach ($f in $files) {
        try {
            $i = Read-JsonFile $f.FullName
            $due = ConvertTo-UtcDateTime ([string]$i.next_attempt_utc)
            if ($Force -or $due -le [DateTime]::UtcNow) { [void](Invoke-FileQueueItem $f.FullName) }
        } catch { Write-Warn "Skipped file queue item $($f.Name): $($_.Exception.Message)" }
    }
}

function Show-Inbox {
    $files = @(Get-ChildItem -LiteralPath $script:Paths.InboxMessages -Filter '*.llmsg' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 20)
    Write-Host ''
    Write-Host 'Recent messages (newest first):' -ForegroundColor Cyan
    if ($files.Count -eq 0) { Write-Host '  No messages yet.' }
    foreach ($f in $files) {
        try {
            $m = Read-JsonFile $f.FullName
            $text = Unprotect-Base64ToText ([string]$m.text_protected)
            $oneLine = ($text -replace '[\r\n]+',' ')
            if ($oneLine.Length -gt 120) { $oneLine = $oneLine.Substring(0,120) + '...' }
            Write-Host ('  {0} | {1}: {2}' -f $m.received_utc,$m.from_name,$oneLine)
        } catch { Write-Host ('  ' + $f.Name + ' [unreadable]') }
    }
    Write-Host ''
    Write-Host ('Files inbox: ' + $script:Paths.InboxFiles)
}

function Test-PeerConnectivity {
    $peer = Select-Peer
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $reply = Invoke-PeerRequest -Peer $peer -Operation 'ping' -Payload ([ordered]@{ client_utc=Get-UtcIso; client_version=$script:Version })
    $sw.Stop()
    Write-Info "$($peer.display_name) is authenticated and online. Round trip: $($sw.ElapsedMilliseconds) ms; version $($reply.version)."
}

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = [Security.Principal.WindowsPrincipal]::new($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}



function Get-LegacyFirewallRuleNames([int]$Port) {
    return @(
        "LAN Router Comms Safe TCP $Port",
        "LAN Link v2 TCP $Port (Private LocalSubnet)",
        "LAN Router Comms v2 TCP $Port (Private LocalSubnet)"
    )
}

function Get-FirewallRuleName([int]$Port) { return "LAN Router Comms TCP $Port (Private LocalSubnet)" }


function Invoke-ElevatedMode([string]$TargetMode,[int]$Port) {
    if ($TargetMode -notin @('FirewallAdd','FirewallRemove')) { throw 'Unsupported elevated mode.' }
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $args = '-NoLogo -NoProfile -File "{0}" -Mode {1} -Port {2}' -f $script:ScriptPath.Replace('"','\"'),$TargetMode,$Port
    $proc = Start-Process -FilePath $ps -ArgumentList $args -Verb RunAs -WorkingDirectory $script:Root -Wait -PassThru
    if ($proc.ExitCode -ne 0) { throw "The elevated firewall action failed or was cancelled (exit code $($proc.ExitCode))." }
}


function Get-FirewallRuleBackup {
    param([Parameter(Mandatory=$true)]$Rule)
    $portFilter = @($Rule | Get-NetFirewallPortFilter -ErrorAction Stop)
    $addressFilter = @($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
    $applicationFilter = @($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
    $serviceFilter = @($Rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
    $interfaceFilter = @($Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
    $interfaceTypeFilter = @($Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
    $securityFilter = @($Rule | Get-NetFirewallSecurityFilter -ErrorAction Stop)
    if ($portFilter.Count -ne 1 -or $addressFilter.Count -ne 1 -or $applicationFilter.Count -ne 1 -or
        $serviceFilter.Count -ne 1 -or $interfaceFilter.Count -ne 1 -or $interfaceTypeFilter.Count -ne 1 -or
        $securityFilter.Count -ne 1) {
        throw "Cannot safely back up firewall rule '$($Rule.DisplayName)' because its filter topology is unexpected."
    }
    return [pscustomobject]@{
        Name          = [string]$Rule.Name
        DisplayName   = [string]$Rule.DisplayName
        Group         = [string]$Rule.Group
        Direction     = $Rule.Direction
        Action        = $Rule.Action
        Enabled       = $Rule.Enabled
        Profile       = $Rule.Profile
        Description   = [string]$Rule.Description
        EdgeTraversalPolicy = $Rule.EdgeTraversalPolicy
        LooseSourceMapping  = $Rule.LooseSourceMapping
        LocalOnlyMapping    = $Rule.LocalOnlyMapping
        Owner               = [string]$Rule.Owner
        Protocol      = $portFilter[0].Protocol
        LocalPort     = @($portFilter[0].LocalPort)
        RemotePort    = @($portFilter[0].RemotePort)
        IcmpType      = @($portFilter[0].IcmpType)
        DynamicTarget = $portFilter[0].DynamicTarget
        LocalAddress  = @($addressFilter[0].LocalAddress)
        RemoteAddress = @($addressFilter[0].RemoteAddress)
        Program       = [string]$applicationFilter[0].Program
        Package       = [string]$applicationFilter[0].Package
        Service       = [string]$serviceFilter[0].Service
        InterfaceAlias = @($interfaceFilter[0].InterfaceAlias)
        InterfaceType  = $interfaceTypeFilter[0].InterfaceType
        Authentication = $securityFilter[0].Authentication
        Encryption     = $securityFilter[0].Encryption
        OverrideBlockRules = $securityFilter[0].OverrideBlockRules
        LocalUser      = @($securityFilter[0].LocalUser)
        RemoteUser     = @($securityFilter[0].RemoteUser)
        RemoteMachine  = @($securityFilter[0].RemoteMachine)
    }
}

function Restore-FirewallRuleBackup {
    param([Parameter(Mandatory=$true)]$Backup)
    $parameters = @{
        DisplayName   = $Backup.DisplayName
        Direction     = $Backup.Direction
        Action        = $Backup.Action
        Enabled       = $Backup.Enabled
        Profile       = $Backup.Profile
        Protocol      = $Backup.Protocol
        LocalAddress  = @($Backup.LocalAddress)
        RemoteAddress = $Backup.RemoteAddress
        Authentication = $Backup.Authentication
        Encryption     = $Backup.Encryption
        OverrideBlockRules = $Backup.OverrideBlockRules
    }
    foreach ($propertyName in @('Name','Group','Description','EdgeTraversalPolicy','LooseSourceMapping','LocalOnlyMapping','Owner')) {
        $value = $Backup.$propertyName
        if ($null -ne $value -and -not ($value -is [string] -and [string]::IsNullOrWhiteSpace($value))) { $parameters[$propertyName] = $value }
    }
    $protocolText = [string]$Backup.Protocol
    if ($protocolText -in @('TCP','UDP','6','17')) {
        $parameters.LocalPort = @($Backup.LocalPort)
        $parameters.RemotePort = @($Backup.RemotePort)
    }
    if ($protocolText -in @('ICMPv4','ICMPv6','1','58')) { $parameters.IcmpType = @($Backup.IcmpType) }
    foreach ($propertyName in @('DynamicTarget','Program','Package','Service','InterfaceAlias','InterfaceType','LocalUser','RemoteUser','RemoteMachine')) {
        $value = $Backup.$propertyName
        $values = @($value)
        $meaningful = @($values | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) -and [string]$_ -ne 'Any' })
        if ($meaningful.Count) { $parameters[$propertyName] = $value }
    }
    [void](New-NetFirewallRule @parameters -ErrorAction Stop)
}


function Add-ScopedFirewallRule {
    param([int]$Port)
    if (-not (Test-IsAdministrator)) {
        Invoke-ElevatedMode -TargetMode 'FirewallAdd' -Port $Port
        $after = Get-FirewallRuleSummary $Port
        if (-not $after.compliant) { throw ('Elevated action returned, but the exact firewall rule is not compliant: ' + (@($after.drift) -join '; ')) }
        Write-Info 'The elevated firewall action completed and was re-verified in the parent process.'
        return
    }
    $name = Get-FirewallRuleName $Port
    $managedNames = @($name) + @(Get-LegacyFirewallRuleNames $Port)
    $priorRules = @()
    foreach ($oldName in $managedNames) {
        $priorRules += @(Get-NetFirewallRule -DisplayName $oldName -ErrorAction SilentlyContinue)
    }
    $priorRuleBackups = @()
    foreach ($priorRule in $priorRules) {
        $priorRuleBackups += @(Get-FirewallRuleBackup -Rule $priorRule)
    }
    $program = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        foreach ($oldName in $managedNames) {
            @(Get-NetFirewallRule -DisplayName $oldName -ErrorAction SilentlyContinue) | Remove-NetFirewallRule -ErrorAction Stop
        }
        [void](New-NetFirewallRule -DisplayName $name -Group 'LAN Router Comms' -Direction Inbound -Action Allow -Enabled True `
            -Profile Private -Protocol TCP -LocalPort $Port -RemoteAddress LocalSubnet -Program $program `
            -Description 'Visible LAN Router Comms receiver; private profile and local subnet only.' -ErrorAction Stop)
        $summary = Get-FirewallRuleSummary $Port
        if (-not $summary.compliant) { throw ('Firewall rule was created but did not pass exact-scope verification: ' + ($summary.drift -join '; ')) }
        Write-Info "Added and verified narrow Windows Firewall rule: TCP $Port, Private profile, LocalSubnet, Windows PowerShell only."
    } catch {
        $originalError = $_.Exception.Message
        $rollbackErrors = New-Object System.Collections.Generic.List[string]
        foreach ($oldName in $managedNames) {
            try { @(Get-NetFirewallRule -DisplayName $oldName -ErrorAction SilentlyContinue) | Remove-NetFirewallRule -ErrorAction Stop }
            catch { [void]$rollbackErrors.Add("remove partial rule '$oldName': $($_.Exception.Message)") }
        }
        foreach ($backup in $priorRuleBackups) {
            try { Restore-FirewallRuleBackup -Backup $backup }
            catch { [void]$rollbackErrors.Add("restore '$($backup.DisplayName)': $($_.Exception.Message)") }
        }
        if ($rollbackErrors.Count) {
            throw ("Firewall update failed: $originalError Rollback was incomplete: " + ($rollbackErrors.ToArray() -join '; '))
        }
        throw "Firewall update failed; previous matching rules were restored. $originalError"
    }
}


function Remove-ScopedFirewallRule {
    param([int]$Port)
    if (-not (Test-IsAdministrator)) {
        Invoke-ElevatedMode -TargetMode 'FirewallRemove' -Port $Port
        $remaining = @()
        foreach ($name in @((Get-FirewallRuleName $Port)) + @(Get-LegacyFirewallRuleNames $Port)) { $remaining += @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) }
        if ($remaining.Count) { throw "The elevated action returned, but $($remaining.Count) matching firewall rule(s) remain." }
        Write-Info 'The elevated firewall removal completed and was re-verified in the parent process.'
        return
    }
    $removed = 0
    foreach ($name in @((Get-FirewallRuleName $Port)) + @(Get-LegacyFirewallRuleNames $Port)) {
        $rules = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
        if ($rules.Count) { $rules | Remove-NetFirewallRule; $removed += $rules.Count }
    }
    if ($removed) { Write-Info "Removed $removed current/legacy LAN Router Comms Windows Firewall rule(s)." }
    else { Write-Info 'No matching LAN Router Comms Windows Firewall rule was present.' }
}

function Show-FirewallMenu {
    $cfg = Get-AppConfig
    while ($true) {
        Write-Host ''
        Write-Host 'Firewall helper' -ForegroundColor Cyan
        Write-Host "  Receiver executable: $env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        Write-Host "  Inbound protocol/port: TCP $($cfg.listen_port)"
        Write-Host '  Scope: Private network + LocalSubnet only'
        Write-Host '  1. Add/repair the narrow Windows Firewall rule (admin prompt)'
        Write-Host '  2. Remove the Windows Firewall rule (admin prompt)'
        Write-Host '  3. Show third-party firewall checklist'
        Write-Host '  0. Back'
        $c = Read-Host 'Choose'
        switch ($c) {
            '1' { Add-ScopedFirewallRule ([int]$cfg.listen_port) }
            '2' { Remove-ScopedFirewallRule ([int]$cfg.listen_port) }
            '3' {
                Write-Host ''
                Write-Warn 'LAN Router Comms does not bypass, disable, or reconfigure endpoint security.'
                Write-Host 'If a third-party firewall prompts, approve only this inbound application rule:'
                Write-Host "  Program: $env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
                Write-Host "  Protocol: TCP; local port $($cfg.listen_port); remote: your local/private subnet only"
                Write-Host '  Network trust: Private/Trusted home router network only'
                Write-Host 'Keep all other unsolicited inbound traffic blocked.'
            }
            '0' { return }
            default { Write-Warn 'Invalid choice.' }
        }
    }
}


function Get-FirewallRuleSummary([int]$Port) {
    $name = Get-FirewallRuleName $Port
    try {
        $rules = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)
        $legacyRules = @()
        foreach ($legacyName in @(Get-LegacyFirewallRuleNames $Port)) { $legacyRules += @(Get-NetFirewallRule -DisplayName $legacyName -ErrorAction SilentlyContinue) }
        if ($rules.Count -ne 1) {
            $drift = @("Expected one current rule; found $($rules.Count).")
            if ($legacyRules.Count) { $drift += "$($legacyRules.Count) legacy rule(s) also exist; use Add/repair to consolidate them" }
            return [ordered]@{ present=(($rules.Count + $legacyRules.Count) -gt 0); compliant=$false; display_name=$name; drift=$drift; current_count=$rules.Count; legacy_count=$legacyRules.Count }
        }
        $rule = $rules[0]
        $pfList = @($rule | Get-NetFirewallPortFilter)
        $afList = @($rule | Get-NetFirewallAddressFilter)
        $appList = @($rule | Get-NetFirewallApplicationFilter)
        $pf = if ($pfList.Count) { $pfList[0] } else { $null }
        $af = if ($afList.Count) { $afList[0] } else { $null }
        $app = if ($appList.Count) { $appList[0] } else { $null }
        $expectedProgram = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
        $drift = @()
        if ($legacyRules.Count) { $drift += "$($legacyRules.Count) legacy rule(s) also exist; use Add/repair to consolidate them" }
        if ($pfList.Count -ne 1) { $drift += "expected one port filter; found $($pfList.Count)" }
        if ($afList.Count -ne 1) { $drift += "expected one address filter; found $($afList.Count)" }
        if ($appList.Count -ne 1) { $drift += "expected one application filter; found $($appList.Count)" }
        if ([string]$rule.Enabled -ne 'True') { $drift += 'rule is disabled' }
        if ([string]$rule.Action -ne 'Allow') { $drift += 'action is not Allow' }
        if ([string]$rule.Direction -ne 'Inbound') { $drift += 'direction is not Inbound' }
        if ([string]$rule.Profile -ne 'Private') { $drift += "profile is $($rule.Profile), not Private" }
        if ($pf -and [string]$pf.Protocol -notin @('TCP','6')) { $drift += "protocol is $($pf.Protocol), not TCP" }
        if ($pf -and [string]$pf.LocalPort -ne [string]$Port) { $drift += "local port is $($pf.LocalPort), not $Port" }
        if ($af -and [string]$af.RemoteAddress -ne 'LocalSubnet') { $drift += "remote address is $($af.RemoteAddress), not LocalSubnet" }
        if ($app -and -not [string]::Equals([string]$app.Program,$expectedProgram,[StringComparison]::OrdinalIgnoreCase)) { $drift += 'program path differs from Windows PowerShell' }
        return [ordered]@{
            present=$true; compliant=($drift.Count -eq 0); display_name=$name; drift=$drift; current_count=$rules.Count; legacy_count=$legacyRules.Count;
            enabled=[string]$rule.Enabled; action=[string]$rule.Action; profile=[string]$rule.Profile; direction=[string]$rule.Direction;
            protocol=$(if($pf){[string]$pf.Protocol}else{''}); local_port=$(if($pf){[string]$pf.LocalPort}else{''});
            remote_address=$(if($af){[string]$af.RemoteAddress}else{''}); program=$(if($app){[string]$app.Program}else{''})
        }
    } catch { return [ordered]@{ present=$false; compliant=$false; display_name=$name; drift=@($_.Exception.Message); error=$_.Exception.Message } }
}


function Get-HealthReport {
    $checks = New-Object System.Collections.Generic.List[object]
    function Add-Check([string]$Name,[string]$Status,[string]$Detail) { [void]$checks.Add([pscustomobject]@{name=$Name;status=$Status;detail=$Detail}) }
    if ($PSVersionTable.PSVersion.Major -ge 5) { Add-Check 'PowerShell' 'PASS' ([string]$PSVersionTable.PSVersion) } else { Add-Check 'PowerShell' 'FAIL' 'Windows PowerShell 5.1 or newer is required.' }
    if ($env:OS -eq 'Windows_NT') { Add-Check 'Operating system' 'PASS' ([Environment]::OSVersion.VersionString) } else { Add-Check 'Operating system' 'FAIL' 'Windows is required.' }
    try {
        $compatList = New-Object System.Collections.Generic.List[object]
        [void]$compatList.Add([pscustomobject]@{ value = 1 })
        $compatArray = $compatList.ToArray()
        if ($compatArray.Count -eq 1) { Add-Check 'PowerShell 5.1 collection boundary' 'PASS' 'Generic lists are converted with ToArray before pipeline return.' }
        else { Add-Check 'PowerShell 5.1 collection boundary' 'FAIL' 'Generic collection conversion returned an unexpected count.' }
    } catch { Add-Check 'PowerShell 5.1 collection boundary' 'FAIL' $_.Exception.Message }
    try {
        $probe = Join-Path $script:Paths.Temp ('health-' + [guid]::NewGuid().ToString('N') + '.tmp')
        Write-DurableText $probe 'ok'; Remove-Item $probe -Force
        Add-Check 'Atomic state write' 'PASS' 'Folder-local durable write succeeded.'
    } catch { Add-Check 'Atomic state write' 'FAIL' $_.Exception.Message }
    try {
        if ((Test-AcceptableTlsProtocol ([Security.Authentication.SslProtocols]::Tls12)) -and -not (Test-AcceptableTlsProtocol ([Security.Authentication.SslProtocols]::Tls11))) {
            Add-Check 'TLS policy' 'PASS' 'OS-negotiated protocol with an enforced TLS 1.2 minimum; TLS 1.3 is accepted when the OS/runtime negotiates it.'
        } else { Add-Check 'TLS policy' 'FAIL' 'TLS minimum-version policy self-check failed.' }
    } catch { Add-Check 'TLS policy' 'FAIL' $_.Exception.Message }
    try {
        [void][Net.Sockets.IOControlCode]::KeepAliveValues
        Add-Check 'TCP keepalive support' 'PASS' 'Per-connection Windows keepalive control is available.'
    } catch { Add-Check 'TCP keepalive support' 'WARN' 'Per-connection keepalive control is unavailable; I/O timeouts remain active.' }
    try {
        $sample = New-RandomBytes 32; $round = Unprotect-Base64ToBytes (Protect-BytesToBase64 $sample)
        if (Test-FixedTimeEqual $sample $round) { Add-Check 'DPAPI' 'PASS' 'Current-user protection round trip succeeded.' } else { Add-Check 'DPAPI' 'FAIL' 'Round trip mismatch.' }
    } catch { Add-Check 'DPAPI' 'FAIL' $_.Exception.Message }
    try {
        $id=Get-LocalIdentity; $cert=Get-IdentityCertificate
        try {
            $days=($cert.NotAfter.ToUniversalTime()-[DateTime]::UtcNow).TotalDays
            if ($days -gt 30) { Add-Check 'TLS identity' 'PASS' ("Pinned certificate valid for {0:N0} more days." -f $days) }
            else { Add-Check 'TLS identity' 'WARN' ("Certificate expires in {0:N0} days." -f $days) }
        } finally { $cert.Dispose() }
    } catch { Add-Check 'TLS identity' 'FAIL' $_.Exception.Message }
    $ips=@(Get-LocalPrivateIPv4s)
    if ($ips.Count) { Add-Check 'Private LAN IPv4' 'PASS' ($ips -join ', ') } else { Add-Check 'Private LAN IPv4' 'FAIL' 'No RFC1918 address found.' }
    try {
        $profiles=@(Get-NetConnectionProfile -ErrorAction Stop | Where-Object {$_.IPv4Connectivity -ne 'Disconnected'})
        if (@($profiles | Where-Object {$_.NetworkCategory -eq 'Private'}).Count -gt 0) { Add-Check 'Network profile' 'PASS' 'At least one connected profile is Private.' }
        else { Add-Check 'Network profile' 'WARN' 'No connected Private profile detected. Do not open LAN Router Comms on a Public profile.' }
    } catch { Add-Check 'Network profile' 'WARN' 'Could not read network profiles.' }
    $cfg=Get-AppConfig
    $audit=Get-ConfigAudit
    if ($audit.status -eq 'PASS') { Add-Check 'Config schema' 'PASS' 'lanlink-config-v2.2; no unknown/missing keys.' } else { Add-Check 'Config schema' $audit.status ((@('schema='+$audit.schema,'unknown='+(@($audit.unknown_keys) -join ','),'missing='+(@($audit.missing_keys) -join ',')) -join '; ')) }
    Add-Check 'TCP keepalive policy' 'PASS' ("idle=$($cfg.tcp_keepalive_time_ms) ms; interval=$($cfg.tcp_keepalive_interval_ms) ms; I/O timeout=$($cfg.io_timeout_ms) ms.")
    Add-Check 'Receiver session guard' 'PASS' ("max_seconds=$($cfg.max_session_seconds); max_requests=$($cfg.max_session_requests); resumable transfer reconnect remains safe.")
    try {
        $retryProbe = Get-RetryDelaySeconds -Attempts 1 -Config $cfg
        if ($retryProbe -ge 10 -and $retryProbe -le 20) { Add-Check 'Retry jitter' 'PASS' ("exponential backoff plus up to $($cfg.retry_jitter_percent)% jitter; probe=$retryProbe seconds.") }
        else { Add-Check 'Retry jitter' 'FAIL' ("Unexpected retry probe: $retryProbe seconds.") }
    } catch { Add-Check 'Retry jitter' 'FAIL' $_.Exception.Message }
    $fw=Get-FirewallRuleSummary ([int]$cfg.listen_port)
    if ($fw.compliant) { Add-Check 'Windows Firewall rule' 'PASS' 'Exact Private/LocalSubnet/TCP/port/program scope verified.' }
    elseif ($fw.present) { Add-Check 'Windows Firewall rule' 'WARN' ('Rule drift: ' + (@($fw.drift) -join '; ')) }
    else { Add-Check 'Windows Firewall rule' 'WARN' 'Rule is absent. It is needed only on the receiving PC.' }
    $peers=@(Get-AllPeers).Count
    Add-Check 'Paired peers' 'PASS' ("$peers paired PC(s).")
    $qm=@(Get-ChildItem $script:Paths.OutboxMessages -Filter '*.json' -File -ErrorAction SilentlyContinue).Count
    $qf=@(Get-ChildItem $script:Paths.OutboxFiles -Filter '*.json' -File -ErrorAction SilentlyContinue).Count
    $staleSources = 0
    foreach ($q in @(Get-ChildItem $script:Paths.OutboxFiles -Filter '*.json' -File -ErrorAction SilentlyContinue)) { try { $qi=Read-JsonFile $q.FullName; if (-not (Test-Path -LiteralPath (Resolve-QueuedSourcePath $qi) -PathType Leaf)) { $staleSources++ } } catch { $staleSources++ } }
    Add-Check 'Queued source portability' $(if($staleSources){'WARN'}else{'PASS'}) ("$staleSources stale/unresolvable queued source path(s).")
    Add-Check 'Delivery queue' $(if(($qm+$qf)-eq 0){'PASS'}else{'WARN'}) ("$qm message(s), $qf file(s) pending.")
    $partials=@(Get-ChildItem $script:Paths.Incoming -Filter '*.json' -File -ErrorAction SilentlyContinue).Count
    Add-Check 'Partial receives' $(if($partials -eq 0){'PASS'}else{'WARN'}) ("$partials resumable partial transfer(s).")
    try {
        $space = Get-FreeSpaceInfo -Path $script:Root
        [long]$reserve = [long]$cfg.min_free_space_mb * 1MB
        if ([long]$space.available_bytes -gt ($reserve + 512MB)) { Add-Check 'Incoming disk reserve' 'PASS' ("{0:N1} GiB free; {1:N1} GiB reserved before accepting incoming data." -f ([long]$space.available_bytes/1GB),($reserve/1GB)) }
        else { Add-Check 'Incoming disk reserve' 'WARN' ("{0:N1} MiB free; configured reserve is {1:N1} MiB." -f ([long]$space.available_bytes/1MB),($reserve/1MB)) }
    } catch { Add-Check 'Incoming disk reserve' 'WARN' $_.Exception.Message }
    Add-Check 'Run trace' 'PASS' ("run_id=$script:RunId elapsed_ms=$($script:RunStopwatch.ElapsedMilliseconds)")
    return $checks.ToArray()
}

function Show-HealthReport {
    $healthChecks = @(Get-HealthReport)
    Write-Host ''
    Write-Host 'LAN Router Comms health' -ForegroundColor Cyan
    foreach($c in $healthChecks) {
        $color = switch($c.status){'PASS'{'Green'}'WARN'{'Yellow'}default{'Red'}}
        Write-Host ('  [{0}] {1}: {2}' -f $c.status,$c.name,$c.detail) -ForegroundColor $color
    }
    $fails=@($healthChecks|Where-Object {$_.status -eq 'FAIL'}).Count
    $warns=@($healthChecks|Where-Object {$_.status -eq 'WARN'}).Count
    Write-Host ''
    if($fails){ Write-Fail "$fails blocking health failure(s); $warns warning(s)." }
    elseif($warns){ Write-Warn "Core health is usable with $warns warning(s)." }
    else{ Write-Info 'All health checks passed.' }
    return $healthChecks
}



function Get-ExistingLocalIdentity {
    $path = Get-IdentityPath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try {
        $id = Read-JsonFile $path
        if ($id.schema -ne 'lanlink-identity-v2' -or -not (Test-GuidText ([string]$id.peer_id))) { return $null }
        return $id
    } catch { return $null }
}

function Get-DiagnosticConfigSnapshot {
    $defaults = Get-DefaultConfig
    $path = Get-ConfigPath
    $result = [ordered]@{}
    foreach ($key in $defaults.Keys) { $result[$key] = $defaults[$key] }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        return [pscustomobject]@{ effective=[pscustomobject]$result; source='defaults-in-memory'; status='WARN'; error='settings.json is missing; the support export did not create it.' }
    }
    try {
        $raw = Read-JsonFile $path
        $names = @($raw.PSObject.Properties.Name)
        foreach ($key in $defaults.Keys) { if ($key -in $names) { $result[$key] = $raw.$key } }
        $normalized = Normalize-AppConfig $result
        return [pscustomobject]@{ effective=[pscustomobject]$normalized; source='settings.json-read-only'; status='PASS'; error='' }
    } catch {
        return [pscustomobject]@{ effective=[pscustomobject]$result; source='defaults-after-read-error'; status='FAIL'; error=$_.Exception.Message }
    }
}

function Get-DiagnosticHealthSnapshot {
    $checks = New-Object System.Collections.Generic.List[object]
    function Add-DiagCheck([string]$Name,[string]$Status,[string]$Detail) { [void]$checks.Add([pscustomobject]@{name=$Name;status=$Status;detail=$Detail}) }
    if ($PSVersionTable.PSVersion.Major -ge 5) { Add-DiagCheck 'PowerShell' 'PASS' ([string]$PSVersionTable.PSVersion) } else { Add-DiagCheck 'PowerShell' 'FAIL' 'Windows PowerShell 5.1 or newer is required.' }
    if ($env:OS -eq 'Windows_NT') { Add-DiagCheck 'Operating system' 'PASS' ([Environment]::OSVersion.VersionString) } else { Add-DiagCheck 'Operating system' 'FAIL' 'Windows is required.' }
    $cfgSnap = Get-DiagnosticConfigSnapshot
    Add-DiagCheck 'Config read' ([string]$cfgSnap.status) (([string]$cfgSnap.source) + $(if($cfgSnap.error){': '+[string]$cfgSnap.error}else{''}))
    $id = Get-ExistingLocalIdentity
    if ($id -and (Test-Path -LiteralPath (Get-PfxPath) -PathType Leaf)) { Add-DiagCheck 'TLS identity files' 'PASS' 'Existing identity and PFX are present; the support export did not create or rotate them.' }
    else { Add-DiagCheck 'TLS identity files' 'WARN' 'Identity is incomplete or not initialized; the support export made no repair.' }
    $ips=@(Get-LocalPrivateIPv4s)
    if ($ips.Count) { Add-DiagCheck 'Private LAN IPv4' 'PASS' ($ips -join ', ') } else { Add-DiagCheck 'Private LAN IPv4' 'WARN' 'No RFC1918 address found.' }
    try {
        $profiles=@(Get-NetConnectionProfile -ErrorAction Stop | Where-Object {$_.IPv4Connectivity -ne 'Disconnected'})
        if (@($profiles | Where-Object {$_.NetworkCategory -eq 'Private'}).Count -gt 0) { Add-DiagCheck 'Network profile' 'PASS' 'At least one connected profile is Private.' }
        else { Add-DiagCheck 'Network profile' 'WARN' 'No connected Private profile detected.' }
    } catch { Add-DiagCheck 'Network profile' 'WARN' 'Could not read network profiles.' }
    $fw=Get-FirewallRuleSummary ([int]$cfgSnap.effective.listen_port)
    if ($fw.compliant) { Add-DiagCheck 'Windows Firewall rule' 'PASS' 'Exact scoped rule verified.' }
    elseif ($fw.present) { Add-DiagCheck 'Windows Firewall rule' 'WARN' ('Rule drift: ' + (@($fw.drift) -join '; ')) }
    else { Add-DiagCheck 'Windows Firewall rule' 'WARN' 'Rule absent or unreadable; the support export made no change.' }
    $qm=@(Get-ChildItem $script:Paths.OutboxMessages -Filter '*.json' -File -ErrorAction SilentlyContinue).Count
    $qf=@(Get-ChildItem $script:Paths.OutboxFiles -Filter '*.json' -File -ErrorAction SilentlyContinue).Count
    Add-DiagCheck 'Delivery queue' $(if(($qm+$qf)-eq 0){'PASS'}else{'WARN'}) ("$qm message(s), $qf file(s) pending.")
    Add-DiagCheck 'Read-only collection' 'PASS' 'No config, identity, peer, queue, receipt, firewall, or endpoint-security state was repaired or changed.'
    return $checks.ToArray()
}

function Redact-DiagnosticText([string]$Text) {
    $v=[string]$Text
    if($env:USERPROFILE){$v=$v.Replace($env:USERPROFILE,'[USERPROFILE]')}
    if($script:Root){$v=$v.Replace($script:Root,'[PROJECT_ROOT]')}
    if($env:COMPUTERNAME){$v=$v -replace [regex]::Escape([string]$env:COMPUTERNAME),'[LOCAL-PC]'}
    $v=[regex]::Replace($v,'\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b','[PRIVATE-IP]')
    $v=[regex]::Replace($v,'(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b','[REDACTED-ID]')
    $v=[regex]::Replace($v,'(?i)\b[0-9a-f]{64}\b','[SHA256]')
    $v=[regex]::Replace($v,'(?i)\b(?:[0-9a-f]{2}-){5}[0-9a-f]{2}\b','[MAC]')
    $v=[regex]::Replace($v,'(?i)(?:[A-Z]:\\[^\r\n\t\"]+)','[LOCAL-PATH]')
    try {
        $id=Get-ExistingLocalIdentity
        if($id -and $id.display_name){$v=$v -replace [regex]::Escape([string]$id.display_name),'[LOCAL-PC]'}
        foreach($peer in @(Get-AllPeerRecords -ReadOnly)){if($peer.display_name){$v=$v -replace [regex]::Escape([string]$peer.display_name),'[PEER]'}}
    }catch{}
    return $v
}


function Export-SupportDiagnostics {
    $stamp=[DateTime]::UtcNow.ToString('yyyyMMdd_HHmmss_fff')
    $shortRun=$script:RunId.Substring(0,8)
    $stage=Join-Path $script:Paths.Temp ('SupportExport_'+$stamp+'_'+$shortRun)
    $zipTmp=Join-Path $script:Paths.Diagnostics ('.LAN_Router_Comms_v'+$script:Version+'_SupportExport_'+$stamp+'_'+$shortRun+'.zip.tmp')
    $zipFinal=Join-Path $script:Paths.Diagnostics ('LAN_Router_Comms_v'+$script:Version+'_SupportExport_'+$stamp+'_'+$shortRun+'.zip')
    [void](New-Item -ItemType Directory -Path $stage -Force)
    $errors = New-Object System.Collections.Generic.List[string]
    function Try-Section([string]$Name,[scriptblock]$Action) { try { & $Action } catch { [void]$errors.Add($Name + ': ' + $_.Exception.Message) } }
    try {
        Write-DurableText (Join-Path $stage '01_README.txt') "LAN Router Comms support export`r`nVersion: $script:Version`r`nSensitivity: support-redacted`r`nRead-only, redacted, fail-isolated support bundle.`r`nSecrets and message/file contents are excluded. Review every file before sharing.`r`nCreated UTC: $(Get-UtcIso)`r`nRun ID: $script:RunId`r`n"
        Try-Section 'version' { Write-JsonFile (Join-Path $stage '02_version_run.json') ([ordered]@{app=$script:AppName;version=$script:Version;protocol=$script:ProtocolVersion;run_id=$script:RunId;started_utc=$script:RunStartedUtc.ToString('o');created_utc=Get-UtcIso;elapsed_ms=$script:RunStopwatch.ElapsedMilliseconds;root='[PROJECT_ROOT]';sensitivity='support-redacted'}) }
        Try-Section 'health' { $h=@();foreach($c in @(Get-DiagnosticHealthSnapshot)){$h += [ordered]@{name=$c.name;status=$c.status;detail=Redact-DiagnosticText ([string]$c.detail)}};Write-JsonFile (Join-Path $stage '03_health.json') $h }
        Try-Section 'config' { $snap=Get-DiagnosticConfigSnapshot;$cfg=$snap.effective;$audit=Get-ConfigAudit;Write-JsonFile (Join-Path $stage '04_effective_config.json') ([ordered]@{schema=$cfg.schema;listen_port=$cfg.listen_port;preferred_ip=$(if($cfg.preferred_ip){'[PRIVATE-IP]'}else{''});limits=[ordered]@{max_message_bytes=$cfg.max_message_bytes;file_chunk_bytes=$cfg.file_chunk_bytes;connect_timeout_ms=$cfg.connect_timeout_ms;io_timeout_ms=$cfg.io_timeout_ms;tcp_keepalive_time_ms=$cfg.tcp_keepalive_time_ms;tcp_keepalive_interval_ms=$cfg.tcp_keepalive_interval_ms;max_session_seconds=$cfg.max_session_seconds;max_session_requests=$cfg.max_session_requests;min_free_space_mb=$cfg.min_free_space_mb;retry_jitter_percent=$cfg.retry_jitter_percent;max_pending_messages=$cfg.max_pending_messages;max_pending_files=$cfg.max_pending_files};audit=$audit}) }
        Try-Section 'platform' { Write-DurableText (Join-Path $stage '05_platform.txt') ("OS: $([Environment]::OSVersion.VersionString)`r`nPowerShell: $($PSVersionTable.PSVersion)`r`n.NET: $([Environment]::Version)`r`nArchitecture: $env:PROCESSOR_ARCHITECTURE`r`nExecution policy scopes:`r`n" + ((Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-String))) }
        Try-Section 'network' { $profiles=Get-NetConnectionProfile -ErrorAction SilentlyContinue|Select-Object InterfaceAlias,NetworkCategory,IPv4Connectivity;Write-DurableText (Join-Path $stage '06_network.txt') (Redact-DiagnosticText("Private IPv4 count: $(@(Get-LocalPrivateIPv4s).Count)`r`n"+($profiles|Format-Table -AutoSize|Out-String))) }
        Try-Section 'firewall' { $snap=Get-DiagnosticConfigSnapshot;$cfg=$snap.effective;$fw=Get-FirewallRuleSummary ([int]$cfg.listen_port);Write-JsonFile (Join-Path $stage '07_firewall.json') $fw }
        Try-Section 'identity' { $id=Get-ExistingLocalIdentity;if($id){Write-JsonFile (Join-Path $stage '08_identity_summary.json') ([ordered]@{display_name='[LOCAL-PC]';peer_id='[REDACTED-ID]';cert_sha256='[SHA256]';cert_not_after_utc=$id.cert_not_after_utc})}else{Write-JsonFile (Join-Path $stage '08_identity_summary.json') ([ordered]@{status='not initialized';note='The support export made no identity change.'})} }
        Try-Section 'peers' { $s=@();$i=0;foreach($p in @(Get-AllPeerRecords -ReadOnly)){$i++;$s += [ordered]@{display_name=('PEER-'+$i);enabled=($p.enabled -ne $false);last_seen_utc=$p.last_seen_utc;port=$p.port;cert='[SHA256]'}};Write-JsonFile (Join-Path $stage '09_peer_summary.json') $s }
        Try-Section 'queue' { $stale=0;$external=0;foreach($q in @(Get-ChildItem $script:Paths.OutboxFiles -Filter '*.json' -File -ErrorAction SilentlyContinue)){try{$x=Read-JsonFile $q.FullName;if($x.source_path_kind -eq 'external-absolute'){$external++};if(-not(Test-Path -LiteralPath (Resolve-QueuedSourcePath $x) -PathType Leaf)){$stale++}}catch{$stale++}};Write-JsonFile (Join-Path $stage '10_queue_state.json') ([ordered]@{messages=@(Get-ChildItem $script:Paths.OutboxMessages -Filter '*.json' -File -ErrorAction SilentlyContinue).Count;files=@(Get-ChildItem $script:Paths.OutboxFiles -Filter '*.json' -File -ErrorAction SilentlyContinue).Count;external_absolute_sources=$external;stale_sources=$stale;partial_manifests=@(Get-ChildItem $script:Paths.Incoming -Filter '*.json' -File -ErrorAction SilentlyContinue).Count;sent_receipts=@(Get-ChildItem $script:Paths.Sent -Filter '*.json' -File -ErrorAction SilentlyContinue).Count}) }
        Try-Section 'inventory' { $snap=Get-DiagnosticConfigSnapshot;$cfg=$snap.effective;$deadline=[DateTime]::UtcNow.AddSeconds([int]$cfg.max_diag_seconds);$count=0;$bytes=[long]0;$truncated=$false;foreach($f in @(Get-ChildItem -LiteralPath $script:Root -Recurse -File -ErrorAction SilentlyContinue)){if($f.FullName.StartsWith($stage,[StringComparison]::OrdinalIgnoreCase)){continue};$count++;$bytes+=[long]$f.Length;if($count -ge [int]$cfg.max_diag_inventory_files -or [DateTime]::UtcNow -ge $deadline){$truncated=$true;break}};Write-JsonFile (Join-Path $stage '11_bounded_inventory.json') ([ordered]@{files_seen=$count;bytes_seen=$bytes;truncated=$truncated;file_cap=[int]$cfg.max_diag_inventory_files;seconds_cap=[int]$cfg.max_diag_seconds;project_root='[PROJECT_ROOT]'}) }
        Try-Section 'timing' { Write-JsonFile (Join-Path $stage '12_timing.json') ([ordered]@{run_id=$script:RunId;start_utc=$script:RunStartedUtc.ToString('o');export_utc=Get-UtcIso;elapsed_ms=$script:RunStopwatch.ElapsedMilliseconds;clock='Stopwatch monotonic for elapsed; UTC wall clock for correlation';last_progress='diagnostic export';shutdown_reason=''}) }
        Try-Section 'logs' { $tail='No log available.';$latest=Get-ChildItem $script:Paths.Logs -Filter '*.log' -File -ErrorAction SilentlyContinue|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1;if($latest){$tail=Redact-DiagnosticText((Get-Content -LiteralPath $latest.FullName -Tail 200 -ErrorAction SilentlyContinue) -join "`r`n")};Write-DurableText (Join-Path $stage '13_log_tail_redacted.txt') $tail }
        if($errors.Count){Write-DurableText (Join-Path $stage '14_collector_errors.txt') (($errors.ToArray() -join "`r`n")+"`r`n")}
        $checksumLines=@();foreach($f in Get-ChildItem $stage -File|Sort-Object Name){$checksumLines += ('{0} *{1}' -f (Get-Sha256HexFromFile $f.FullName),$f.Name)};Write-DurableText (Join-Path $stage '15_checksums.sha256') (($checksumLines -join "`r`n")+"`r`n")
        if(@(Get-ChildItem $stage -File).Count -gt 20){throw 'Support export file-count invariant failed.'}
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($stage,$zipTmp,[IO.Compression.CompressionLevel]::Optimal,$false)
        $z=[IO.Compression.ZipFile]::OpenRead($zipTmp)
        try {
            if($z.Entries.Count -lt 1 -or $z.Entries.Count -gt 20){throw 'Diagnostic ZIP entry-count verification failed.'}
            $buffer=New-Object byte[] 65536
            foreach($entry in $z.Entries){$stream=$entry.Open();try{while($stream.Read($buffer,0,$buffer.Length) -gt 0){}}finally{$stream.Dispose()}}
        } finally {$z.Dispose()}
        if(Test-Path $zipFinal){throw 'A diagnostic ZIP collision occurred; no existing export was overwritten.'}
        [IO.File]::Move($zipTmp,$zipFinal)
        Write-Host ("[+] Support diagnostics created, CRC-read, and verified: " + $zipFinal)
        return $zipFinal
    } catch {
        throw
    } finally {
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $zipTmp -Force -ErrorAction SilentlyContinue
    }
}


function Invoke-StartupTest {
    Write-Host "LAN Router Comms v$script:Version startup test" -ForegroundColor Cyan
    Write-Host "Run ID: $script:RunId"
    $fails = 0
    $stage = 'health'
    try {
        Write-Host '[1/2] Running runtime health checks...' -ForegroundColor DarkCyan
        $checks = @(Show-HealthReport)
        $fails = @($checks | Where-Object { $_.status -eq 'FAIL' }).Count
    } catch {
        $type = $_.Exception.GetType().FullName
        $where = [string]$_.InvocationInfo.PositionMessage
        Write-Fail ("Startup health stage failed: " + $_.Exception.Message)
        Write-Host ("Exception type: " + $type) -ForegroundColor Red
        if ($where) { Write-Host $where -ForegroundColor DarkYellow }
        if ($_.ScriptStackTrace) { Write-Host ("Stack: " + $_.ScriptStackTrace) -ForegroundColor DarkYellow }
        Write-AppLog -Level ERROR -Message ("StartupTest stage=health type=" + $type + " error=" + $_.Exception.ToString() + " stack=" + $_.ScriptStackTrace)
        return 1
    }

    $stage = 'support-export'
    try {
        Write-Host '[2/2] Running read-only support-export smoke check...' -ForegroundColor DarkCyan
        $probe = Export-SupportDiagnostics
        Write-Info "Diagnostic export smoke test passed: $probe"
    } catch {
        $type = $_.Exception.GetType().FullName
        $where = [string]$_.InvocationInfo.PositionMessage
        Write-Fail ('Diagnostic export smoke test failed: ' + $_.Exception.Message)
        Write-Host ("Exception type: " + $type) -ForegroundColor Red
        if ($where) { Write-Host $where -ForegroundColor DarkYellow }
        if ($_.ScriptStackTrace) { Write-Host ("Stack: " + $_.ScriptStackTrace) -ForegroundColor DarkYellow }
        Write-AppLog -Level ERROR -Message ("StartupTest stage=support-export type=" + $type + " error=" + $_.Exception.ToString() + " stack=" + $_.ScriptStackTrace)
        $fails++
    }
    if ($fails) { Write-Fail 'Startup test failed.'; return 1 }
    Write-Info 'Startup test passed. Run LAN_Router_Comms.ps1 with -Mode Menu to continue.'
    return 0
}


function Show-About {
    Write-Host ''
    Write-Host "LAN Router Comms v$script:Version - Adaptive Transport Guard" -ForegroundColor Cyan
    Write-Host 'Prime directive:'
    Write-Host '  Reliably deliver authenticated text and files between paired Windows PCs on one trusted private router LAN.'
    Write-Host 'Design boundaries:'
    Write-Host '  No cloud, remote shell, hidden service, autorun, port forwarding, endpoint-security bypass, or firewall disablement.'
    Write-Host 'Stability layer:'
    Write-Host '  Durable bounded queues, dedupe, resumable files, identity fail-closed recovery, OS-negotiated TLS with a TLS 1.2 floor, TCP keepalive, disk admission, session quotas, jittered retry, exact firewall checks, and redacted support exports.'
}

function Pause-LANRouterComms { [void](Read-Host 'Press Enter to continue') }


function Show-MainMenu {
    $null=Get-LocalIdentity
    try { Retry-PendingQueue -StartupSweep } catch { Write-AppLog -Level WARN -Message ('Due-queue startup retry failed: ' + $_.Exception.Message) }
    while($true){
        Clear-Host
        Write-Host '============================================================' -ForegroundColor DarkCyan
        Write-Host " LAN Router Comms v$script:Version - Adaptive Transport Guard" -ForegroundColor Cyan
        Write-Host ' Authenticated router-LAN messaging and resumable file handoff'
        Write-Host '============================================================' -ForegroundColor DarkCyan
        Write-Host '  1. Health and status'
        Write-Host '  2. Start receiver in this window'
        Write-Host '  3. Create one-time pairing invitation'
        Write-Host '  4. Import pairing invitation'
        Write-Host '  5. Send text message'
        Write-Host '  6. Send file (resumable + SHA-256 receipt)'
        Write-Host '  7. Retry pending delivery queue'
        Write-Host '  8. View recent inbox'
        Write-Host '  9. Test an authenticated peer'
        Write-Host ' 10. Manage/revoke paired PCs'
        Write-Host ' 11. Firewall helper'
        Write-Host ' 12. Export redacted support diagnostics'
        Write-Host ' 13. About / prime directive'
        Write-Host '  0. Exit'
        Write-Host ''
        $choice=Read-Host 'Choose an option'
        try{
            switch($choice){
                '1'{[void](Show-HealthReport);Pause-LANRouterComms}
                '2'{$cfg=Get-AppConfig;Start-Receiver -ListenPort ([int]$cfg.listen_port) -InteractiveAddress;return}
                '3'{New-PairingInvite;Pause-LANRouterComms}
                '4'{Import-PairingInvite;Pause-LANRouterComms}
                '5'{Send-TextMessageInteractive;Pause-LANRouterComms}
                '6'{Send-FileInteractive;Pause-LANRouterComms}
                '7'{Retry-PendingQueue -Force;Pause-LANRouterComms}
                '8'{Show-Inbox;Pause-LANRouterComms}
                '9'{Test-PeerConnectivity;Pause-LANRouterComms}
                '10'{Show-PeerManagement}
                '11'{Show-FirewallMenu}
                '12'{[void](Export-SupportDiagnostics);Pause-LANRouterComms}
                '13'{Show-About;Pause-LANRouterComms}
                '0'{return}
                default{Write-Warn 'Invalid choice.';Start-Sleep -Seconds 1}
            }
        }catch{Write-Fail $_.Exception.Message;Write-AppLog -Level ERROR -Message $_.Exception.ToString();Pause-LANRouterComms}
    }
}

if ($Mode -eq 'SupportExport') {
    foreach ($path in @($script:Paths.Temp,$script:Paths.Diagnostics)) { if (-not (Test-Path -LiteralPath $path)) { [void](New-Item -ItemType Directory -Path $path -Force) } }
} else {
    Initialize-AppFolders
    Invoke-Housekeeping
    Write-AppLog -Level INFO -Message "Process start app=$script:AppName version=$script:Version mode=$Mode root=$script:Root"
}
try {
    switch($Mode){
        'Menu'          { Show-MainMenu }
        'Receiver'      { $cfg=Get-AppConfig; $listen=$(if($PSBoundParameters.ContainsKey('Port')){$Port}else{[int]$cfg.listen_port}); Start-Receiver -ListenPort $listen }
        'StartupTest'   { exit (Invoke-StartupTest) }
        'Health'        { $c=@(Show-HealthReport); if(@($c|Where-Object{$_.status -eq 'FAIL'}).Count){exit 1} }
        'RetryQueue'    { Retry-PendingQueue -Force }
        'SupportExport' { [void](Export-SupportDiagnostics) }
        'FirewallAdd'   { Add-ScopedFirewallRule -Port $Port }
        'FirewallRemove'{ Remove-ScopedFirewallRule -Port $Port }
    }
} catch {
    if ($Mode -eq 'SupportExport') { Write-Host ('[X] ' + $_.Exception.Message) -ForegroundColor Red }
    else { Write-Fail $_.Exception.Message; Write-AppLog -Level ERROR -Message $_.Exception.ToString() }
    exit 1
}
