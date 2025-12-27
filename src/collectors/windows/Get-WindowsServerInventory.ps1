<#
.SYNOPSIS
  Collects a lightweight, read-only Windows Server inventory (OS, roles, services, scheduled tasks, disks, NICs).

.DESCRIPTION
  Designed for migration-readiness assessments. Produces a structured object per host that can be exported
  to JSON/CSV by the caller. Uses CIM/WMI for most inventory. For Scheduled Tasks, uses PowerShell remoting
  (Invoke-Command) by default; can fall back to SCHTASKS.exe for environments without WinRM.

  This script is Windows PowerShell 5.1 compatible.

.OUTPUTS
  PSCustomObject (one per computer)

.EXAMPLE
  # Local inventory
  .\Get-WindowsServerInventory.ps1

.EXAMPLE
  # Remote inventory (WinRM enabled)
  .\Get-WindowsServerInventory.ps1 -ComputerName SRV01,SRV02 -IncludeRoles -IncludeServices -IncludeScheduledTasks |
    ConvertTo-Json -Depth 6 | Out-File C:\Reports\Inventory.json -Encoding utf8

.EXAMPLE
  # Remote scheduled tasks without WinRM (uses schtasks)
  .\Get-WindowsServerInventory.ps1 -ComputerName SRV01 -IncludeScheduledTasks -UseSchtasksForScheduledTasks

.NOTES
  Recommended: run from an account with local admin rights on targets for best fidelity.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
  [string[]]$ComputerName = @($env:COMPUTERNAME),

  [Parameter(Mandatory=$false)]
  [pscredential]$Credential,

  [Parameter(Mandatory=$false)]
  [int]$CimOperationTimeoutSec = 30,

  # What to collect (keep lightweight by default)
  [Parameter(Mandatory=$false)]
  [switch]$IncludeRoles,

  [Parameter(Mandatory=$false)]
  [switch]$IncludeServices,

  [Parameter(Mandatory=$false)]
  [switch]$IncludeScheduledTasks,

  [Parameter(Mandatory=$false)]
  [switch]$IncludeDisks = $true,

  [Parameter(Mandatory=$false)]
  [switch]$IncludeNics  = $true,

  # Services options
  [Parameter(Mandatory=$false)]
  [ValidateSet("All","Running","Stopped")]
  [string]$ServiceState = "Running",

  # Scheduled tasks options
  [Parameter(Mandatory=$false)]
  [switch]$ExcludeMicrosoftScheduledTasks,

  [Parameter(Mandatory=$false)]
  [string]$TaskPath = "\",

  [Parameter(Mandatory=$false)]
  [string]$TaskName = "*",

  [Parameter(Mandatory=$false)]
  [switch]$UseSchtasksForScheduledTasks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-CimSessionSafe {
  param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$false)][pscredential]$Cred,
    [Parameter(Mandatory=$true)][int]$TimeoutSec
  )

  $opt = New-CimSessionOption -Protocol Dcom
  if ($Cred) {
    return New-CimSession -ComputerName $Target -Credential $Cred -SessionOption $opt -OperationTimeoutSec $TimeoutSec
  }
  return New-CimSession -ComputerName $Target -SessionOption $opt -OperationTimeoutSec $TimeoutSec
}

function Get-ScheduledTasksViaRemoting {
  param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$false)][pscredential]$Cred,
    [Parameter(Mandatory=$true)][string]$TaskPath,
    [Parameter(Mandatory=$true)][string]$TaskName,
    [Parameter(Mandatory=$true)][bool]$ExcludeMicrosoft
  )

  $sb = {
    param($TaskPath, $TaskName, $ExcludeMicrosoft)

    # Get-ScheduledTask exists on modern Windows; if not, return empty with note.
    if (-not (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue)) {
      return @()
    }

    $tasks = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue

    if ($ExcludeMicrosoft) {
      $tasks = $tasks | Where-Object {
        # Common Microsoft paths
        ($_.TaskPath -notlike "\Microsoft\*") -and
        ($_.TaskPath -notlike "\Windows\*")
      }
    }

    foreach ($t in $tasks) {
      $info = $null
      try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop } catch {}

      [pscustomobject]@{
        TaskName   = $t.TaskName
        TaskPath   = $t.TaskPath
        State      = $t.State.ToString()
        Author     = $t.Author
        Principal  = $t.Principal.UserId
        RunLevel   = $t.Principal.RunLevel.ToString()
        LastRun    = if ($info) { $info.LastRunTime } else { $null }
        NextRun    = if ($info) { $info.NextRunTime } else { $null }
        LastResult = if ($info) { $info.LastTaskResult } else { $null }
      }
    }
  }

  if ($Cred) {
    return Invoke-Command -ComputerName $Target -Credential $Cred -ScriptBlock $sb -ArgumentList $TaskPath,$TaskName,$ExcludeMicrosoft -ErrorAction Stop
  }
  return Invoke-Command -ComputerName $Target -ScriptBlock $sb -ArgumentList $TaskPath,$TaskName,$ExcludeMicrosoft -ErrorAction Stop
}

function Get-ScheduledTasksViaSchtasks {
  param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$true)][string]$TaskPath,
    [Parameter(Mandatory=$true)][string]$TaskName,
    [Parameter(Mandatory=$true)][bool]$ExcludeMicrosoft
  )

  # SCHTASKS returns CSV when /FO CSV. /V adds columns.
  # Note: filtering by TaskPath/TaskName is limited; we’ll filter after retrieval.
  $args = @("/Query","/S",$Target,"/FO","CSV","/V")
  $raw = & schtasks.exe @args 2>$null
  if (-not $raw) { return @() }

  $rows = $raw | ConvertFrom-Csv

  # Normalize fields we care about; names can vary slightly by OS locale/version
  $nameField = @("TaskName","Task Name") | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
  $statusField = @("Status","Scheduled Task State") | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
  $authorField = @("Author") | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
  $runAsField = @("Run As User","Run As") | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
  $lastRunField = @("Last Run Time","Last Run") | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
  $nextRunField = @("Next Run Time","Next Run") | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
  $lastResultField = @("Last Result") | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1

  $out = @()

  foreach ($r in $rows) {
    $fullName = if ($nameField) { $r.$nameField } else { $null }
    if (-not $fullName) { continue }

    # TaskName includes path in SCHTASKS output (e.g., \Microsoft\Windows\Defrag\ScheduledDefrag)
    if ($ExcludeMicrosoft -and ($fullName -like "\Microsoft\*")) { continue }

    # Filter by path/name patterns
    if ($TaskPath -and ($TaskPath -ne "\") -and ($fullName -notlike ($TaskPath.TrimEnd("\") + "\*"))) { continue }
    if ($TaskName -and ($TaskName -ne "*")) {
      $leaf = Split-Path -Path $fullName -Leaf
      if ($leaf -notlike $TaskName) { continue }
    }

    $out += [pscustomobject]@{
      TaskName   = Split-Path -Path $fullName -Leaf
      TaskPath   = (Split-Path -Path $fullName -Parent) + "\"
      State      = if ($statusField) { $r.$statusField } else { $null }
      Author     = if ($authorField) { $r.$authorField } else { $null }
      Principal  = if ($runAsField) { $r.$runAsField } else { $null }
      RunLevel   = $null
      LastRun    = if ($lastRunField) { $r.$lastRunField } else { $null }
      NextRun    = if ($nextRunField) { $r.$nextRunField } else { $null }
      LastResult = if ($lastResultField) { $r.$lastResultField } else { $null }
    }
  }

  return $out
}

function Get-WindowsRolesSafe {
  param(
    [Parameter(Mandatory=$true)][string]$Target,
    [Parameter(Mandatory=$false)][pscredential]$Cred
  )

  # Prefer remoting for roles/features because Get-WindowsFeature is local to the OS.
  $sb = {
    if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
      Get-WindowsFeature |
        Where-Object { $_.Installed -eq $true } |
        Select-Object -Property Name, DisplayName, FeatureType
    } else {
      @()
    }
  }

  try {
    if ($Cred) {
      return Invoke-Command -ComputerName $Target -Credential $Cred -ScriptBlock $sb -ErrorAction Stop
    }
    return Invoke-Command -ComputerName $Target -ScriptBlock $sb -ErrorAction Stop
  } catch {
    # If WinRM not available, return empty and let caller record error
    return @()
  }
}

process {
  foreach ($cn in $ComputerName) {
    $errors = New-Object System.Collections.Generic.List[string]
    $cim = $null

    $result = [ordered]@{
      ComputerName = $cn
      CollectedAt  = (Get-Date).ToString("s")
      OS           = $null
      Hardware     = $null
      Disks        = @()
      Nics         = @()
      Roles        = @()
      Services     = @()
      ScheduledTasks = @()
      Summary      = $null
      Errors       = @()
    }

    try {
      $cim = New-CimSessionSafe -Target $cn -Cred $Credential -TimeoutSec $CimOperationTimeoutSec

      # OS
      try {
        $os = Get-CimInstance -CimSession $cim -ClassName Win32_OperatingSystem
        $result.OS = [pscustomobject]@{
          Caption        = $os.Caption
          Version        = $os.Version
          BuildNumber    = $os.BuildNumber
          InstallDate    = $os.InstallDate
          LastBootUpTime = $os.LastBootUpTime
          OSArchitecture = $os.OSArchitecture
          Locale         = $os.Locale
          TimeZone       = $os.CurrentTimeZone
        }
      } catch { $errors.Add("OS: $($_.Exception.Message)") | Out-Null }

      # Hardware
      try {
        $cs = Get-CimInstance -CimSession $cim -ClassName Win32_ComputerSystem
        $bios = Get-CimInstance -CimSession $cim -ClassName Win32_BIOS
        $cpu = Get-CimInstance -CimSession $cim -ClassName Win32_Processor | Select-Object -First 1

        $result.Hardware = [pscustomobject]@{
          Manufacturer     = $cs.Manufacturer
          Model            = $cs.Model
          Domain           = $cs.Domain
          DomainRole       = $cs.DomainRole
          TotalPhysicalGB  = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
          CpuName          = $cpu.Name
          CpuCores         = $cpu.NumberOfCores
          CpuLogical       = $cpu.NumberOfLogicalProcessors
          BiosSerialNumber = $bios.SerialNumber
        }
      } catch { $errors.Add("Hardware: $($_.Exception.Message)") | Out-Null }

      # Disks
      if ($IncludeDisks) {
        try {
          $ld = Get-CimInstance -CimSession $cim -ClassName Win32_LogicalDisk -Filter "DriveType=3"
          $result.Disks = $ld | ForEach-Object {
            [pscustomobject]@{
              DeviceId    = $_.DeviceID
              VolumeName  = $_.VolumeName
              FileSystem  = $_.FileSystem
              SizeGB      = if ($_.Size) { [math]::Round(($_.Size / 1GB), 2) } else { $null }
              FreeGB      = if ($_.FreeSpace) { [math]::Round(($_.FreeSpace / 1GB), 2) } else { $null }
              FreePct     = if ($_.Size -and $_.FreeSpace) { [math]::Round(($_.FreeSpace / $_.Size) * 100, 2) } else { $null }
            }
          }
        } catch { $errors.Add("Disks: $($_.Exception.Message)") | Out-Null }
      }

      # NICs
      if ($IncludeNics) {
        try {
          $nics = Get-CimInstance -CimSession $cim -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
          $result.Nics = $nics | ForEach-Object {
            [pscustomobject]@{
              Description = $_.Description
              MACAddress  = $_.MACAddress
              DHCPEnabled = $_.DHCPEnabled
              IPAddress   = @($_.IPAddress) -join ", "
              SubnetMask  = @($_.IPSubnet) -join ", "
              Gateway     = @($_.DefaultIPGateway) -join ", "
              DNSServers  = @($_.DNSServerSearchOrder) -join ", "
              DNSDomain   = $_.DNSDomain
            }
          }
        } catch { $errors.Add("NICs: $($_.Exception.Message)") | Out-Null }
      }

      # Roles/Features
      if ($IncludeRoles) {
        try {
          $roles = Get-WindowsRolesSafe -Target $cn -Cred $Credential
          $result.Roles = $roles
          if (-not $roles -or $roles.Count -eq 0) {
            $errors.Add("Roles: No roles returned (WinRM may be disabled or ServerManager module unavailable).") | Out-Null
          }
        } catch { $errors.Add("Roles: $($_.Exception.Message)") | Out-Null }
      }

      # Services
      if ($IncludeServices) {
        try {
          $svc = Get-CimInstance -CimSession $cim -ClassName Win32_Service
          if ($ServiceState -eq "Running") { $svc = $svc | Where-Object { $_.State -eq "Running" } }
          elseif ($ServiceState -eq "Stopped") { $svc = $svc | Where-Object { $_.State -eq "Stopped" } }

          $result.Services = $svc | Select-Object `
            @{n="Name";e={$_.Name}}, `
            @{n="DisplayName";e={$_.DisplayName}}, `
            @{n="State";e={$_.State}}, `
            @{n="StartMode";e={$_.StartMode}}, `
            @{n="StartName";e={$_.StartName}}, `
            @{n="PathName";e={$_.PathName}}
        } catch { $errors.Add("Services: $($_.Exception.Message)") | Out-Null }
      }

      # Scheduled Tasks
      if ($IncludeScheduledTasks) {
        try {
          if ($UseSchtasksForScheduledTasks) {
            $result.ScheduledTasks = Get-ScheduledTasksViaSchtasks -Target $cn -TaskPath $TaskPath -TaskName $TaskName -ExcludeMicrosoft ([bool]$ExcludeMicrosoftScheduledTasks)
          } else {
            $result.ScheduledTasks = Get-ScheduledTasksViaRemoting -Target $cn -Cred $Credential -TaskPath $TaskPath -TaskName $TaskName -ExcludeMicrosoft ([bool]$ExcludeMicrosoftScheduledTasks)
          }
        } catch {
          $errors.Add("ScheduledTasks: $($_.Exception.Message) (Tip: try -UseSchtasksForScheduledTasks if WinRM is unavailable.)") | Out-Null
        }
      }

    } catch {
      $errors.Add("Connection: $($_.Exception.Message)") | Out-Null
    } finally {
      if ($cim) {
        try { $cim | Remove-CimSession -ErrorAction SilentlyContinue } catch {}
      }
    }

    # Summary
    $result.Summary = [pscustomobject]@{
      DiskCount          = @($result.Disks).Count
      NicCount           = @($result.Nics).Count
      RoleCount          = @($result.Roles).Count
      ServiceCount       = @($result.Services).Count
      ScheduledTaskCount = @($result.ScheduledTasks).Count
      ErrorCount         = $errors.Count
    }

    $result.Errors = @($errors)

    [pscustomobject]$result
  }
}
