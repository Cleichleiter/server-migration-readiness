<#
.SYNOPSIS
  Analyzes Windows Server dependencies (network listeners, service bindings, identity signals, and workload fingerprints).

.DESCRIPTION
  Read-only analyzer intended for migration readiness. Designed to pair with:
    - src/collectors/windows/Get-WindowsServerInventory.ps1
    - src/exporters/Export-InventoryReport.ps1

  This v1 focuses on evidence-based signals:
    - TCP listeners and owning process/service mapping (local + remote via WinRM)
    - Identity context (domain join, domain role, DNS domain/servers from inventory)
    - Workload fingerprints (IIS/SQL/RDS/etc.) using services/roles when available
    - Risk signals (e.g., public-facing ports, RDS present, domain-account services)

  Output:
    Returns the original inventory object with an added .Dependencies property (unless -PassThru:$false).

.NOTES
  - Network listener analysis uses WinRM remoting to execute Get-NetTCPConnection on targets.
    If WinRM is unavailable, it will record an error and continue.
  - Windows PowerShell 5.1 compatible.

.EXAMPLE
  # Analyze dependencies for a local run and export
  .\src\collectors\windows\Get-WindowsServerInventory.ps1 -IncludeServices -IncludeRoles |
    .\src\analyzers\dependency\Analyze-WindowsServerDependencies.ps1 |
    .\src\exporters\Export-InventoryReport.ps1 -EnvironmentName "Example"

.EXAMPLE
  # Remote run with credentials
  $cred = Get-Credential
  .\src\collectors\windows\Get-WindowsServerInventory.ps1 -ComputerName SRV01,SRV02 -Credential $cred -IncludeServices |
    .\src\analyzers\dependency\Analyze-WindowsServerDependencies.ps1 -Credential $cred
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
  [psobject]$InputObject,

  [Parameter(Mandatory=$false)]
  [pscredential]$Credential,

  # If true, uses WinRM to query listeners (recommended). If false, listener analysis is skipped.
  [Parameter(Mandatory=$false)]
  [switch]$IncludeNetworkListeners = $true,

  # Ports that often imply higher migration sensitivity / exposure.
  [Parameter(Mandatory=$false)]
  [int[]]$SensitivePorts = @(53,80,88,135,139,389,443,445,464,636,1433,1521,2049,3306,3389,5432,5985,5986,8080,8443),

  # If true, returns the mutated object. If false, emits only the Dependencies object.
  [Parameter(Mandatory=$false)]
  [switch]$PassThru = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Add-OrReplaceNoteProperty {
  param(
    [Parameter(Mandatory=$true)][psobject]$Obj,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][object]$Value
  )
  if ($Obj.PSObject.Properties.Name -contains $Name) {
    $Obj.$Name = $Value
  } else {
    $Obj | Add-Member -MemberType NoteProperty -Name $Name -Value $Value
  }
}

function Get-ListenerEvidence {
  param(
    [Parameter(Mandatory=$true)][string]$ComputerName,
    [Parameter(Mandatory=$false)][pscredential]$Cred
  )

  $sb = {
    # Collect TCP listeners with owning process and best-effort service mapping
    $listeners = @()

    if (-not (Get-Command -Name Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
      return @()
    }

    # Build PID -> ServiceName mapping
    $pidToServices = @{}
    try {
      $svc = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop
      foreach ($s in $svc) {
        if ($s.ProcessId -and $s.ProcessId -ne 0) {
          if (-not $pidToServices.ContainsKey([int]$s.ProcessId)) {
            $pidToServices[[int]$s.ProcessId] = New-Object System.Collections.Generic.List[string]
          }
          $pidToServices[[int]$s.ProcessId].Add($s.Name) | Out-Null
        }
      }
    } catch {}

    $conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
      $p = $null
      try { $p = Get-Process -Id $c.OwningProcess -ErrorAction Stop } catch {}

      $svcs = @()
      if ($pidToServices.ContainsKey([int]$c.OwningProcess)) {
        $svcs = @($pidToServices[[int]$c.OwningProcess])
      }

      $listeners += [pscustomobject]@{
        LocalAddress  = $c.LocalAddress
        LocalPort     = [int]$c.LocalPort
        RemoteAddress = $c.RemoteAddress
        OwningProcess = [int]$c.OwningProcess
        ProcessName   = if ($p) { $p.ProcessName } else { $null }
        ServiceNames  = $svcs
      }
    }

    return $listeners
  }

  if ($Cred) {
    return Invoke-Command -ComputerName $ComputerName -Credential $Cred -ScriptBlock $sb -ErrorAction Stop
  }
  return Invoke-Command -ComputerName $ComputerName -ScriptBlock $sb -ErrorAction Stop
}

function Detect-Applications {
  param(
    [Parameter(Mandatory=$true)][psobject]$Inv
  )

  $apps = New-Object System.Collections.Generic.HashSet[string]
  $signals = New-Object System.Collections.Generic.List[string]

  $services = @()
  $roles = @()

  try { $services = @($Inv.Services) } catch {}
  try { $roles = @($Inv.Roles) } catch {}

  # Services-based fingerprints (works even without roles)
  $svcNames = @()
  if ($services) {
    $svcNames = $services | ForEach-Object { $_.Name } | Where-Object { $_ } | Select-Object -Unique
  }

  $add = {
    param([string]$Name,[string]$Evidence)
    if ($Name) { [void]$apps.Add($Name) }
    if ($Evidence) { $signals.Add($Evidence) | Out-Null }
  }

  if ($svcNames -contains "W3SVC") { & $add "IIS" "Service:W3SVC" }
  if ($svcNames -contains "WAS") { & $add "IIS" "Service:WAS" }
  if ($svcNames -match '^MSSQL' -or $svcNames -contains "SQLSERVERAGENT") { & $add "SQLServer" "Service:MSSQL*" }
  if ($svcNames -contains "TermService") { & $add "RDS" "Service:TermService" }
  if ($svcNames -contains "LanmanServer") { & $add "FileServer" "Service:LanmanServer" }
  if ($svcNames -contains "DNS") { & $add "DNS" "Service:DNS" }
  if ($svcNames -contains "NTDS") { & $add "ActiveDirectoryDS" "Service:NTDS" }
  if ($svcNames -contains "DHCPServer") { & $add "DHCP" "Service:DHCPServer" }
  if ($svcNames -contains "W32Time") { & $add "TimeService" "Service:W32Time" }

  # Roles/features fingerprints (if present)
  if ($roles -and $roles.Count -gt 0) {
    $roleNames = $roles | ForEach-Object { $_.Name } | Where-Object { $_ } | Select-Object -Unique
    if ($roleNames -contains "AD-Domain-Services") { & $add "ActiveDirectoryDS" "Role:AD-Domain-Services" }
    if ($roleNames -contains "DNS") { & $add "DNS" "Role:DNS" }
    if ($roleNames -contains "DHCP") { & $add "DHCP" "Role:DHCP" }
    if ($roleNames -contains "Web-Server") { & $add "IIS" "Role:Web-Server" }
    if ($roleNames -contains "Remote-Desktop-Services") { & $add "RDS" "Role:Remote-Desktop-Services" }
    if ($roleNames -contains "FS-FileServer") { & $add "FileServer" "Role:FS-FileServer" }
  }

  return [pscustomobject]@{
    Applications = @($apps)
    Signals      = @($signals)
  }
}

function Get-IdentitySignals {
  param([Parameter(Mandatory=$true)][psobject]$Inv)

  $hw = $null
  $nics = @()
  try { $hw = $Inv.Hardware } catch {}
  try { $nics = @($Inv.Nics) } catch {}

  $domain = $null
  $domainRole = $null
  if ($hw) {
    $domain = $hw.Domain
    $domainRole = $hw.DomainRole
  }

  # DomainRole mapping (Win32_ComputerSystem.DomainRole)
  $roleText = $null
  if ($domainRole -ne $null) {
    $roleText = switch ([int]$domainRole) {
      0 { "StandaloneWorkstation" }
      1 { "MemberWorkstation" }
      2 { "StandaloneServer" }
      3 { "MemberServer" }
      4 { "BackupDomainController" }
      5 { "PrimaryDomainController" }
      default { "Unknown" }
    }
  }

  $dnsDomain = $null
  $dnsServers = @()
  if ($nics -and $nics.Count -gt 0) {
    # Prefer first NIC as "primary"
    $dnsDomain = $nics[0].DNSDomain
    $dnsServers = @()
    if ($nics[0].DNSServers) {
      $dnsServers = ($nics[0].DNSServers -split ',\s*') | Where-Object { $_ }
    }
  }

  $domainJoined = $false
  if ($domain -and ($domain -ne $env:COMPUTERNAME) -and ($domain -notmatch 'WORKGROUP')) {
    $domainJoined = $true
  }

  return [pscustomobject]@{
    DomainJoined = $domainJoined
    Domain       = $domain
    DomainRole   = $roleText
    DNSDomain    = $dnsDomain
    DNSServers   = $dnsServers
  }
}

function Get-ServiceAccountRisks {
  param([Parameter(Mandatory=$true)][psobject]$Inv)

  $svcs = @()
  try { $svcs = @($Inv.Services) } catch {}
  if (-not $svcs -or $svcs.Count -eq 0) { return @() }

  $risky = @()
  foreach ($s in $svcs) {
    $acct = $null
    try { $acct = [string]$s.StartName } catch {}
    if ([string]::IsNullOrWhiteSpace($acct)) { continue }

    # Heuristic: domain accounts (contains '\') and not built-in locals
    if ($acct -match '\\' -and $acct -notmatch '^(NT AUTHORITY|LocalSystem|NT Service|LocalService|NetworkService)') {
      $risky += [pscustomobject]@{
        ServiceName  = $s.Name
        DisplayName  = $s.DisplayName
        StartName    = $acct
        StartMode    = $s.StartMode
        State        = $s.State
      }
    }
  }

  return $risky
}

process {
  $cn = $null
  try { $cn = [string]$InputObject.ComputerName } catch {}
  if ([string]::IsNullOrWhiteSpace($cn)) { $cn = $env:COMPUTERNAME }

  $depErrors = New-Object System.Collections.Generic.List[string]

  # Applications / identity from inventory
  $app = Detect-Applications -Inv $InputObject
  $identity = Get-IdentitySignals -Inv $InputObject
  $svcAcctRisks = Get-ServiceAccountRisks -Inv $InputObject

  # Network listeners (remote)
  $listeners = @()
  if ($IncludeNetworkListeners) {
    try {
      $listeners = Get-ListenerEvidence -ComputerName $cn -Cred $Credential
    } catch {
      $depErrors.Add("NetworkListeners: $($_.Exception.Message) (WinRM required for listener analysis)") | Out-Null
      $listeners = @()
    }
  }

  # Derive listener summaries
  $listenerSummary = @()
  $sensitiveHits = @()
  if ($listeners -and $listeners.Count -gt 0) {
    foreach ($l in $listeners) {
      $ports = [int]$l.LocalPort
      $isSensitive = $SensitivePorts -contains $ports
      if ($isSensitive) { $sensitiveHits += $l }

      $listenerSummary += [pscustomobject]@{
        LocalAddress = $l.LocalAddress
        LocalPort    = [int]$l.LocalPort
        ProcessName  = $l.ProcessName
        ServiceNames = if ($l.ServiceNames) { @($l.ServiceNames) } else { @() }
        Sensitive    = $isSensitive
      }
    }
  }

  # Risk signals (simple, explainable)
  $riskSignals = New-Object System.Collections.Generic.List[string]

  if ($identity.DomainRole -match "DomainController") {
    $riskSignals.Add("Host is a Domain Controller (migration requires AD-specific plan).") | Out-Null
  }

  if (($app.Applications -contains "RDS")) {
    $riskSignals.Add("RDS detected (session host/broker components are migration-sensitive).") | Out-Null
  }

  if ($svcAcctRisks.Count -gt 0) {
    $riskSignals.Add("Services running under domain accounts detected (credential/permission dependencies).") | Out-Null
  }

  if ($sensitiveHits.Count -gt 0) {
    $riskSignals.Add("Sensitive/well-known listening ports detected (validate inbound dependencies before cutover).") | Out-Null
  }

  # Build Dependencies object
  $deps = [pscustomobject]@{
    Identity = $identity
    ApplicationsDetected = @($app.Applications)
    ApplicationSignals   = @($app.Signals)
    NetworkListeners = [pscustomobject]@{
      Collected = [bool]$IncludeNetworkListeners
      Count     = @($listenerSummary).Count
      Items     = @($listenerSummary)
      SensitivePortHits = @(
        $sensitiveHits | ForEach-Object {
          [pscustomobject]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = [int]$_.LocalPort
            ProcessName  = $_.ProcessName
            ServiceNames = if ($_.ServiceNames) { @($_.ServiceNames) } else { @() }
          }
        }
      )
    }
    ServiceAccountDependencies = @($svcAcctRisks)
    RiskSignals = @($riskSignals)
    Errors      = @($depErrors)
  }

  if ($PassThru) {
    Add-OrReplaceNoteProperty -Obj $InputObject -Name "Dependencies" -Value $deps
    $InputObject
  } else {
    $deps
  }
}
