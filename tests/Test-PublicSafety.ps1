#requires -Version 5.1
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$files = @(Get-ChildItem -LiteralPath $repo -Filter '*.ps1' -Recurse -File)
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) ("PowerShell parse errors in {0}: {1}" -f $file.FullName, (($errors | ForEach-Object Message) -join '; '))
}

$corePath = Join-Path $repo 'LAN_Router_Comms.ps1'
$core = Get-Content -LiteralPath $corePath -Raw
Assert-True ($core -notmatch '(?i)ExecutionPolicy\s+Bypass') 'The public source must not bypass execution policy.'
Assert-True ($core -match '\$script:MinimumTlsProtocolValue\s*=\s*3072') 'TLS 1.2 minimum must remain enforced.'
Assert-True ($core -match 'HMACSHA256') 'Per-peer HMAC authentication is required.'
Assert-True ($core -match 'DataProtectionScope\]::CurrentUser') 'DPAPI CurrentUser protection is required.'
Assert-True ($core -match 'ExpectedFingerprint') 'Certificate pinning is required.'
Assert-True ($core -match '-Profile Private') 'Firewall rule must remain Private-profile scoped.'
Assert-True ($core -match '-RemoteAddress LocalSubnet') 'Firewall rule must remain LocalSubnet scoped.'
Assert-True ($core -match "TargetMode -notin @\('FirewallAdd','FirewallRemove'\)") 'Elevation must remain limited to firewall add/remove.'
Assert-True ($core -match "'FirewallRemove'\s*\{ Remove-ScopedFirewallRule") 'A direct firewall rollback mode is required.'
Assert-True ($core -match '\$script:MaxTransferBytes\s*=\s*10GB') 'File transfers must retain the practical 10 GiB ceiling.'
Assert-True (([regex]::Matches($core,'-gt\s+\$script:MaxTransferBytes')).Count -ge 2) 'Incoming and outgoing file paths must both enforce the transfer ceiling.'
Assert-True ($core -match 'ValidateRange\(0,10737418240\)') 'Incoming capacity validation must not accept values above 10 GiB.'
Assert-True ($core -match "'SupportExport'") 'The public support-export mode is required.'
Assert-True ($core -match "sensitivity='support-redacted'") 'Generated support metadata must be labeled support-redacted.'

$stalePublicTerms = @(
    'Export20',
    'Norton',
    ('project-' + 'internal'),
    'MANIFEST.sha256',
    'MANIFEST.json',
    'START_LAN_ROUTER_COMMS.bat',
    'STARTUP_TEST.bat',
    'README_START_HERE.md',
    'VERSION.txt'
)
foreach ($term in $stalePublicTerms) {
    Assert-True ($core -notmatch [regex]::Escape($term)) ("Stale package-specific term remains in public source: $term")
}

$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($corePath, [ref]$tokens, [ref]$errors)
$commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
$forbidden = @('New-Service','Set-Service','Register-ScheduledTask','New-ScheduledTask','Disable-NetFirewallRule','Set-NetFirewallProfile','Add-MpPreference','Set-MpPreference')
foreach ($name in $forbidden) {
    Assert-True ($name -notin $commands) ("Forbidden persistence or security-control command found: $name")
}

$addFirewallAst = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Add-ScopedFirewallRule'
}, $true)
Assert-True ($null -ne $addFirewallAst) 'Add-ScopedFirewallRule was not found.'
$addFirewallText = $addFirewallAst.Extent.Text
Assert-True ($addFirewallText -match '\$priorRules') 'Firewall repair must snapshot matching rules before mutation.'
Assert-True ($addFirewallText -match 'Get-FirewallRuleBackup') 'Firewall repair must capture restorable rule properties.'
Assert-True ($addFirewallText -match 'Restore-FirewallRuleBackup') 'Firewall repair must restore prior rules after failure.'
Assert-True ($addFirewallText -match 'catch\s*\{') 'Firewall repair must handle creation or verification failures.'
Assert-True ($core -notmatch '\[string\]\$portFilter\[0\]\.LocalPort') 'Firewall backup must not flatten multi-valued port filters.'
Assert-True ($core -notmatch '\[string\]\$addressFilter\[0\]\.RemoteAddress') 'Firewall backup must not flatten multi-valued address filters.'

# Round-trip a drifted, multi-valued rule through the real snapshot and restore
# helpers while replacing NetSecurity cmdlets with in-memory filters.
foreach ($helperName in @('Get-FirewallRuleBackup','Restore-FirewallRuleBackup')) {
    $helperAst = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $helperName
    }, $true)
    Assert-True ($null -ne $helperAst) ("Firewall helper was not found: $helperName")
    Invoke-Expression $helperAst.Extent.Text
}
$script:mockPortFilter = [pscustomobject]@{ Protocol='TCP'; LocalPort=@('57222','57223'); RemotePort=@('80','443'); IcmpType=@('Any'); DynamicTarget='Any' }
$script:mockAddressFilter = [pscustomobject]@{ LocalAddress=@('10.0.0.5','192.168.1.5'); RemoteAddress=@('10.0.0.0/24','192.168.1.0/24') }
$script:mockApplicationFilter = [pscustomobject]@{ Program='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'; Package='Any' }
$script:mockServiceFilter = [pscustomobject]@{ Service='LanmanServer' }
$script:mockInterfaceFilter = [pscustomobject]@{ InterfaceAlias=@('Ethernet','Wi-Fi') }
$script:mockInterfaceTypeFilter = [pscustomobject]@{ InterfaceType='Wireless' }
$script:mockSecurityFilter = [pscustomobject]@{ Authentication='Required'; Encryption='Dynamic'; OverrideBlockRules=$true; LocalUser=@('D:(A;;CC;;;SY)','D:(A;;CC;;;BA)'); RemoteUser=@('D:(A;;CC;;;AU)'); RemoteMachine=@('D:(A;;CC;;;WD)') }
function Get-NetFirewallPortFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject) process { $script:mockPortFilter } }
function Get-NetFirewallAddressFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject) process { $script:mockAddressFilter } }
function Get-NetFirewallApplicationFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject) process { $script:mockApplicationFilter } }
function Get-NetFirewallServiceFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject) process { $script:mockServiceFilter } }
function Get-NetFirewallInterfaceFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject) process { $script:mockInterfaceFilter } }
function Get-NetFirewallInterfaceTypeFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject) process { $script:mockInterfaceTypeFilter } }
function Get-NetFirewallSecurityFilter { [CmdletBinding()] param([Parameter(ValueFromPipeline=$true)]$InputObject) process { $script:mockSecurityFilter } }
function New-NetFirewallRule {
    [CmdletBinding()]
    param($Name,$DisplayName,$Group,$Direction,$Action,$Enabled,$Profile,$Description,$EdgeTraversalPolicy,$LooseSourceMapping,$LocalOnlyMapping,$Owner,$Protocol,$LocalPort,$RemotePort,$IcmpType,$DynamicTarget,$LocalAddress,$RemoteAddress,$Program,$Package,$Service,$InterfaceAlias,$InterfaceType,$Authentication,$Encryption,$OverrideBlockRules,$LocalUser,$RemoteUser,$RemoteMachine)
    $script:restoredFirewallParameters = @{}
    foreach ($key in $PSBoundParameters.Keys) { if ($key -ne 'ErrorAction') { $script:restoredFirewallParameters[$key] = $PSBoundParameters[$key] } }
}
$mockRule = [pscustomobject]@{
    Name='{11111111-2222-3333-4444-555555555555}'; DisplayName='Drifted LAN Router Comms rule'; Group='LAN Router Comms';
    Direction='Inbound'; Action='Allow'; Enabled='True'; Profile='Domain, Private'; Description='Round-trip fixture';
    EdgeTraversalPolicy='DeferToUser'; LooseSourceMapping=$true; LocalOnlyMapping=$true; Owner='S-1-5-32-544'
}
$backup = Get-FirewallRuleBackup -Rule $mockRule
Restore-FirewallRuleBackup -Backup $backup
Assert-True ((@($script:restoredFirewallParameters.LocalPort) -join '|') -eq '57222|57223') 'Firewall restore lost multi-valued local ports.'
Assert-True ((@($script:restoredFirewallParameters.RemotePort) -join '|') -eq '80|443') 'Firewall restore lost multi-valued remote ports.'
Assert-True ((@($script:restoredFirewallParameters.LocalAddress) -join '|') -eq '10.0.0.5|192.168.1.5') 'Firewall restore lost multi-valued local addresses.'
Assert-True ((@($script:restoredFirewallParameters.RemoteAddress) -join '|') -eq '10.0.0.0/24|192.168.1.0/24') 'Firewall restore lost multi-valued remote addresses.'
Assert-True ((@($script:restoredFirewallParameters.InterfaceAlias) -join '|') -eq 'Ethernet|Wi-Fi') 'Firewall restore lost interface aliases.'
Assert-True ($script:restoredFirewallParameters.Service -eq 'LanmanServer') 'Firewall restore lost the service filter.'
Assert-True ($script:restoredFirewallParameters.EdgeTraversalPolicy -eq 'DeferToUser') 'Firewall restore lost edge-traversal policy.'
Assert-True ($script:restoredFirewallParameters.LooseSourceMapping -eq $true -and $script:restoredFirewallParameters.LocalOnlyMapping -eq $true) 'Firewall restore lost mapping policy fields.'
Assert-True ((@($script:restoredFirewallParameters.LocalUser) -join '|') -eq 'D:(A;;CC;;;SY)|D:(A;;CC;;;BA)') 'Firewall restore lost multi-valued security principals.'

# Execute only the firewall-add function with local mocks. A simulated create
# failure must remove partial state and restore the prior matching rule.
Invoke-Expression $addFirewallText
$script:mockPriorRule = [pscustomobject]@{ DisplayName = 'LAN Router Comms TCP 57222 (Private LocalSubnet)' }
$script:mockRemoveCount = 0
$script:mockRestoreCount = 0
function Test-IsAdministrator { return $true }
function Get-FirewallRuleName { param([int]$Port) return "LAN Router Comms TCP $Port (Private LocalSubnet)" }
function Get-LegacyFirewallRuleNames { param([int]$Port) return @("Legacy $Port") }
function Get-NetFirewallRule {
    [CmdletBinding()]
    param([string]$DisplayName)
    if ($DisplayName -eq $script:mockPriorRule.DisplayName) { return $script:mockPriorRule }
    return @()
}
function Get-FirewallRuleBackup { param($Rule) return [pscustomobject]@{ DisplayName = $Rule.DisplayName } }
function Remove-NetFirewallRule {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline=$true)]$InputObject)
    process { $script:mockRemoveCount++ }
}
function New-NetFirewallRule { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments=$true)]$Arguments) throw 'simulated create failure' }
function Restore-FirewallRuleBackup { param($Backup) $script:mockRestoreCount++ }

$firewallFailure = ''
try { Add-ScopedFirewallRule -Port 57222 } catch { $firewallFailure = $_.Exception.Message }
Assert-True ($firewallFailure -match 'previous matching rules were restored') 'Firewall failure did not report a successful rollback.'
Assert-True ($script:mockRestoreCount -eq 1) 'Firewall failure did not restore the prior matching rule exactly once.'
Assert-True ($script:mockRemoveCount -ge 2) 'Firewall failure did not remove both replaced and partial rule state.'

$example = Get-Content -LiteralPath (Join-Path $repo 'config\settings.example.json') -Raw | ConvertFrom-Json
Assert-True ([string]::IsNullOrWhiteSpace([string]$example.preferred_ip)) 'Example configuration must not contain a real peer address.'

Write-Host ("PASS: parsed {0} PowerShell files and verified LAN security invariants." -f $files.Count) -ForegroundColor Green
