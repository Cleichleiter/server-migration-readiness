<#
.SYNOPSIS
  Exports Windows server inventory objects to a run-stamped report folder (JSON + CSV tables + Markdown summary).

.DESCRIPTION
  Designed to pair with:
    src/collectors/windows/Get-WindowsServerInventory.ps1

  Output convention:
    reports\<RunId>\
      run.json
      summary.md
      raw\<ComputerName>.inventory.json
      tables\inventory.hosts.csv
      tables\inventory.disks.csv
      tables\inventory.nics.csv
      tables\inventory.services.csv   (if present)
      tables\inventory.tasks.csv      (if present)

  Safe defaults:
    - Creates a new run folder. If the folder already exists, behavior is controlled by -Overwrite.

  Windows PowerShell 5.1 compatible.

.PARAMETER InputObject
  Inventory objects (pipeline or parameter). Expected to include the properties emitted by Get-WindowsServerInventory.ps1.

.PARAMETER OutputRoot
  Root output directory. Default: .\reports (relative to current working directory).

.PARAMETER RunId
  Run identifier. If omitted, auto-generated as yyyyMMdd-HHmmss.

.PARAMETER EnvironmentName
  Optional environment tag appended to RunId (sanitized). Example: "Mueller" -> 20251227-104500_Mueller

.PARAMETER Overwrite
  If set, allows overwriting files in an existing run folder.

.PARAMETER DiskFreePctWarn
  Free-space percent threshold for warning callouts in summary.md. Default: 15.

.EXAMPLE
  # Export a local run
  .\Get-WindowsServerInventory.ps1 -IncludeRoles -IncludeServices -IncludeScheduledTasks |
    .\Export-InventoryReport.ps1 -EnvironmentName "Example"

.EXAMPLE
  # Export to a specific root with explicit RunId
  $inv = .\Get-WindowsServerInventory.ps1 -ComputerName SRV01,SRV02 -IncludeServices
  $inv | .\Export-InventoryReport.ps1 -OutputRoot "C:\Reports" -RunId "20251227-RunA" -Overwrite

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
  [psobject]$InputObject,

  [Parameter(Mandatory=$false)]
  [string]$OutputRoot = (Join-Path -Path (Get-Location) -ChildPath "reports"),

  [Parameter(Mandatory=$false)]
  [string]$RunId,

  [Parameter(Mandatory=$false)]
  [string]$EnvironmentName,

  [Parameter(Mandatory=$false)]
  [switch]$Overwrite,

  [Parameter(Mandatory=$false)]
  [int]$DiskFreePctWarn = 15
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

begin {
  function Ensure-Dir {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
      New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
  }

  function Write-TextFile {
    param(
      [Parameter(Mandatory=$true)][string]$Path,
      [Parameter(Mandatory=$true)][string]$Content,
      [Parameter(Mandatory=$true)][bool]$AllowOverwrite
    )
    $parent = Split-Path -Parent $Path
    if ($parent) { Ensure-Dir -Path $parent }

    if ((Test-Path -LiteralPath $Path) -and (-not $AllowOverwrite)) {
      throw "File exists and overwrite is disabled: $Path"
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $utf8NoBom)
  }

  function Write-JsonFile {
    param(
      [Parameter(Mandatory=$true)][string]$Path,
      [Parameter(Mandatory=$true)][object]$Object,
      [Parameter(Mandatory=$true)][bool]$AllowOverwrite,
      [Parameter(Mandatory=$false)][int]$Depth = 8
    )

    $parent = Split-Path -Parent $Path
    if ($parent) { Ensure-Dir -Path $parent }

    if ((Test-Path -LiteralPath $Path) -and (-not $AllowOverwrite)) {
      throw "File exists and overwrite is disabled: $Path"
    }

    $json = $Object | ConvertTo-Json -Depth $Depth
    Write-TextFile -Path $Path -Content $json -AllowOverwrite $AllowOverwrite
  }

  function Sanitize-Token {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    # Replace invalid filename chars with hyphen; collapse whitespace.
    $v = ($Value -replace '[\\/:*?"<>|]', '-') -replace '\s+', ' '
    $v = $v.Trim()
    # Keep it reasonably short for folder names
    if ($v.Length -gt 40) { $v = $v.Substring(0,40).Trim() }
    return $v
  }

  if ([string]::IsNullOrWhiteSpace($RunId)) {
    $RunId = (Get-Date).ToString("yyyyMMdd-HHmmss")
  }

  $envTag = Sanitize-Token -Value $EnvironmentName
  if ($envTag) {
    $RunId = "{0}_{1}" -f $RunId, ($envTag -replace ' ', '')
  }

  $RunPath   = Join-Path -Path $OutputRoot -ChildPath $RunId
  $RawPath   = Join-Path -Path $RunPath -ChildPath "raw"
  $TablesPath= Join-Path -Path $RunPath -ChildPath "tables"

  # Create run folder
  if (Test-Path -LiteralPath $RunPath) {
    if (-not $Overwrite) {
      throw "Run folder already exists: $RunPath (use -Overwrite to allow)"
    }
  } else {
    Ensure-Dir -Path $RunPath
  }

  Ensure-Dir -Path $RawPath
  Ensure-Dir -Path $TablesPath

  $items = New-Object System.Collections.Generic.List[object]
}

process {
  if ($null -ne $InputObject) {
    $items.Add($InputObject) | Out-Null
  }
}

end {
  if ($items.Count -eq 0) {
    throw "No input objects received. Pipe inventory objects into this script."
  }

  # ---- Normalize and export per-host JSON ----
  $hosts = @()
  foreach ($i in $items) {
    $cn = $null
    try { $cn = [string]$i.ComputerName } catch {}
    if ([string]::IsNullOrWhiteSpace($cn)) { $cn = "UNKNOWN" }

    $safeCn = (Sanitize-Token -Value $cn)
    if ([string]::IsNullOrWhiteSpace($safeCn)) { $safeCn = "UNKNOWN" }

    $rawFile = Join-Path $RawPath ("{0}.inventory.json" -f $safeCn)
    Write-JsonFile -Path $rawFile -Object $i -AllowOverwrite ([bool]$Overwrite) -Depth 10

    $hosts += $i
  }

  # ---- Build flattened CSV tables ----

  # hosts table (one row per host)
  $hostRows = $hosts | ForEach-Object {
    $os = $null
    $hw = $null
    $sum = $null
    try { $os = $_.OS } catch {}
    try { $hw = $_.Hardware } catch {}
    try { $sum = $_.Summary } catch {}

    [pscustomobject]@{
      ComputerName     = $_.ComputerName
      CollectedAt      = $_.CollectedAt
      OS_Caption       = if ($os) { $os.Caption } else { $null }
      OS_Version       = if ($os) { $os.Version } else { $null }
      OS_Build         = if ($os) { $os.BuildNumber } else { $null }
      OS_Arch          = if ($os) { $os.OSArchitecture } else { $null }
      LastBootUpTime   = if ($os) { $os.LastBootUpTime } else { $null }
      Manufacturer     = if ($hw) { $hw.Manufacturer } else { $null }
      Model            = if ($hw) { $hw.Model } else { $null }
      Domain           = if ($hw) { $hw.Domain } else { $null }
      TotalPhysicalGB  = if ($hw) { $hw.TotalPhysicalGB } else { $null }
      CpuName          = if ($hw) { $hw.CpuName } else { $null }
      CpuCores         = if ($hw) { $hw.CpuCores } else { $null }
      CpuLogical       = if ($hw) { $hw.CpuLogical } else { $null }
      DiskCount        = if ($sum) { $sum.DiskCount } else { $null }
      NicCount         = if ($sum) { $sum.NicCount } else { $null }
      RoleCount        = if ($sum) { $sum.RoleCount } else { $null }
      ServiceCount     = if ($sum) { $sum.ServiceCount } else { $null }
      ScheduledTaskCount = if ($sum) { $sum.ScheduledTaskCount } else { $null }
      ErrorCount       = if ($sum) { $sum.ErrorCount } else { $null }
    }
  }

  $hostsCsv = Join-Path $TablesPath "inventory.hosts.csv"
  $hostRows | Export-Csv -Path $hostsCsv -NoTypeInformation -Force

  # disks table
  $diskRows = @()
  foreach ($h in $hosts) {
    $cn = [string]$h.ComputerName
    $disks = @()
    try { $disks = @($h.Disks) } catch {}
    foreach ($d in $disks) {
      $diskRows += [pscustomobject]@{
        ComputerName = $cn
        DeviceId     = $d.DeviceId
        VolumeName   = $d.VolumeName
        FileSystem   = $d.FileSystem
        SizeGB       = $d.SizeGB
        FreeGB       = $d.FreeGB
        FreePct      = $d.FreePct
      }
    }
  }
  $disksCsv = Join-Path $TablesPath "inventory.disks.csv"
  $diskRows | Export-Csv -Path $disksCsv -NoTypeInformation -Force

  # nics table
  $nicRows = @()
  foreach ($h in $hosts) {
    $cn = [string]$h.ComputerName
    $nics = @()
    try { $nics = @($h.Nics) } catch {}
    foreach ($n in $nics) {
      $nicRows += [pscustomobject]@{
        ComputerName = $cn
        Description  = $n.Description
        MACAddress   = $n.MACAddress
        DHCPEnabled  = $n.DHCPEnabled
        IPAddress    = $n.IPAddress
        SubnetMask   = $n.SubnetMask
        Gateway      = $n.Gateway
        DNSServers   = $n.DNSServers
        DNSDomain    = $n.DNSDomain
      }
    }
  }
  $nicsCsv = Join-Path $TablesPath "inventory.nics.csv"
  $nicRows | Export-Csv -Path $nicsCsv -NoTypeInformation -Force

  # services table (only if present)
  $svcRows = @()
  foreach ($h in $hosts) {
    $cn = [string]$h.ComputerName
    $svcs = @()
    try { $svcs = @($h.Services) } catch {}
    foreach ($s in $svcs) {
      $svcRows += [pscustomobject]@{
        ComputerName = $cn
        Name         = $s.Name
        DisplayName  = $s.DisplayName
        State        = $s.State
        StartMode    = $s.StartMode
        StartName    = $s.StartName
        PathName     = $s.PathName
      }
    }
  }
  if ($svcRows.Count -gt 0) {
    $svcsCsv = Join-Path $TablesPath "inventory.services.csv"
    $svcRows | Export-Csv -Path $svcsCsv -NoTypeInformation -Force
  }

  # scheduled tasks table (only if present)
  $taskRows = @()
  foreach ($h in $hosts) {
    $cn = [string]$h.ComputerName
    $tasks = @()
    try { $tasks = @($h.ScheduledTasks) } catch {}
    foreach ($t in $tasks) {
      $taskRows += [pscustomobject]@{
        ComputerName = $cn
        TaskName     = $t.TaskName
        TaskPath     = $t.TaskPath
        State        = $t.State
        Author       = $t.Author
        Principal    = $t.Principal
        RunLevel     = $t.RunLevel
        LastRun      = $t.LastRun
        NextRun      = $t.NextRun
        LastResult   = $t.LastResult
      }
    }
  }
  if ($taskRows.Count -gt 0) {
    $tasksCsv = Join-Path $TablesPath "inventory.tasks.csv"
    $taskRows | Export-Csv -Path $tasksCsv -NoTypeInformation -Force
  }

  # ---- run.json metadata ----
  $meta = [ordered]@{
    runId           = $RunId
    environmentName = $EnvironmentName
    startedAt       = $hosts | Select-Object -ExpandProperty CollectedAt -First 1
    exportedAt      = (Get-Date).ToString("s")
    hostCount       = $hosts.Count
    outputRoot      = $OutputRoot
    runPath         = $RunPath
    files = [ordered]@{
      summary = "summary.md"
      raw     = "raw\*.inventory.json"
      tables  = "tables\inventory.*.csv"
    }
    warnings = [ordered]@{
      diskFreePctWarn = $DiskFreePctWarn
    }
  }

  Write-JsonFile -Path (Join-Path $RunPath "run.json") -Object $meta -AllowOverwrite ([bool]$Overwrite) -Depth 6

  # ---- Markdown summary.md ----
  $totalErrors = 0
  foreach ($h in $hosts) {
    try { $totalErrors += @($h.Errors).Count } catch {}
  }

  # Disk warnings
  $lowDisks = $diskRows | Where-Object { $_.FreePct -ne $null -and [double]$_.FreePct -lt $DiskFreePctWarn } |
    Sort-Object FreePct, ComputerName, DeviceId

  # Host error details (top 3 per host)
  $hostErrorSnippets = @()
  foreach ($h in $hosts) {
    $errs = @()
    try { $errs = @($h.Errors) } catch {}
    if ($errs.Count -gt 0) {
      $take = $errs
      if ($take.Count -gt 3) { $take = $take[0..2] }
      $hostErrorSnippets += [pscustomobject]@{
        ComputerName = $h.ComputerName
        ErrorCount   = $errs.Count
        Examples     = ($take -join " | ")
      }
    }
  }

  $summaryLines = New-Object System.Collections.Generic.List[string]
  $summaryLines.Add("# Inventory Summary") | Out-Null
  $summaryLines.Add("") | Out-Null
  $summaryLines.Add(("**Run ID:** {0}" -f $RunId)) | Out-Null
  if (-not [string]::IsNullOrWhiteSpace($EnvironmentName)) {
    $summaryLines.Add(("**Environment:** {0}" -f $EnvironmentName)) | Out-Null
  }
  $summaryLines.Add(("**Exported:** {0}" -f (Get-Date).ToString("s"))) | Out-Null
  $summaryLines.Add(("**Hosts:** {0}" -f $hosts.Count)) | Out-Null
  $summaryLines.Add(("**Total Collection Errors:** {0}" -f $totalErrors)) | Out-Null
  $summaryLines.Add("") | Out-Null

  $summaryLines.Add("## Outputs") | Out-Null
  $summaryLines.Add("") | Out-Null
  $summaryLines.Add("- `run.json` (run metadata)") | Out-Null
  $summaryLines.Add("- `raw\*.inventory.json` (per-host raw objects)") | Out-Null
  $summaryLines.Add("- `tables\inventory.hosts.csv`") | Out-Null
  $summaryLines.Add("- `tables\inventory.disks.csv`") | Out-Null
  $summaryLines.Add("- `tables\inventory.nics.csv`") | Out-Null
  if ($svcRows.Count -gt 0) { $summaryLines.Add("- `tables\inventory.services.csv`") | Out-Null }
  if ($taskRows.Count -gt 0) { $summaryLines.Add("- `tables\inventory.tasks.csv`") | Out-Null }
  $summaryLines.Add("") | Out-Null

  $summaryLines.Add("## Quick Stats") | Out-Null
  $summaryLines.Add("") | Out-Null
  $osCounts = $hostRows | Group-Object OS_Caption | Sort-Object Count -Descending
  if ($osCounts.Count -gt 0) {
    $summaryLines.Add("**OS Distribution**") | Out-Null
    foreach ($g in $osCounts) {
      $name = if ([string]::IsNullOrWhiteSpace($g.Name)) { "(unknown)" } else { $g.Name }
      $summaryLines.Add(("- {0}: {1}" -f $name, $g.Count)) | Out-Null
    }
    $summaryLines.Add("") | Out-Null
  }

  # Disk warnings
  $summaryLines.Add(("## Disk Warnings (FreePct < {0})" -f $DiskFreePctWarn)) | Out-Null
  $summaryLines.Add("") | Out-Null
  if ($lowDisks.Count -eq 0) {
    $summaryLines.Add("No disks under threshold.") | Out-Null
  } else {
    $summaryLines.Add("| Computer | Drive | SizeGB | FreeGB | FreePct |") | Out-Null
    $summaryLines.Add("|---|---:|---:|---:|---:|") | Out-Null
    foreach ($d in $lowDisks) {
      $summaryLines.Add( ("| {0} | {1} | {2} | {3} | {4} |" -f $d.ComputerName, $d.DeviceId, $d.SizeGB, $d.FreeGB, $d.FreePct) ) | Out-Null
    }
  }
  $summaryLines.Add("") | Out-Null

  # Error snippets
  $summaryLines.Add("## Collection Errors (Top Examples)") | Out-Null
  $summaryLines.Add("") | Out-Null
  if ($hostErrorSnippets.Count -eq 0) {
    $summaryLines.Add("No collection errors reported.") | Out-Null
  } else {
    $summaryLines.Add("| Computer | Errors | Examples |") | Out-Null
    $summaryLines.Add("|---|---:|---|") | Out-Null
    foreach ($e in ($hostErrorSnippets | Sort-Object ErrorCount -Descending)) {
      $summaryLines.Add( ("| {0} | {1} | {2} |" -f $e.ComputerName, $e.ErrorCount, ($e.Examples -replace '\|','\|')) ) | Out-Null
    }
  }
  $summaryLines.Add("") | Out-Null

  $summaryLines.Add("## Notes") | Out-Null
  $summaryLines.Add("") | Out-Null
  $summaryLines.Add("- This inventory is **read-only** and intended for migration readiness assessment.") | Out-Null
  $summaryLines.Add("- Missing Roles/Tasks data usually indicates WinRM/module availability constraints.") | Out-Null
  $summaryLines.Add("- Use the CSV tables for analysis and the raw JSON for detailed evidence.") | Out-Null

  $summaryPath = Join-Path $RunPath "summary.md"
  Write-TextFile -Path $summaryPath -Content ($summaryLines -join "`r`n") -AllowOverwrite ([bool]$Overwrite)

  Write-Host "Export complete:"
  Write-Host ("  RunPath: {0}" -f $RunPath)
  Write-Host ("  Raw:     {0}" -f $RawPath)
  Write-Host ("  Tables:  {0}" -f $TablesPath)
  Write-Host ("  Hosts:   {0}" -f $hosts.Count)
}
