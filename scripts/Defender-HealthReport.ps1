# Defender-HealthReport.ps1
# Collects Microsoft Defender status, detections and events, then writes
# a text summary and two CSV files. Run in PowerShell as administrator.
#
# Usage:  .\Defender-HealthReport.ps1            (last 7 days, personal names hidden)
#         .\Defender-HealthReport.ps1 -Days 1    (last 24 hours)
#         .\Defender-HealthReport.ps1 -NoRedact  (keep real user and computer names)

param(
    [int]$Days = 7,
    [switch]$NoRedact
)

# ---------- Settings ----------
$ReportDir = 'C:\DefenderLab\reports'
$Stamp     = Get-Date -Format 'yyyy-MM-dd_HHmm'
$LogName   = 'Microsoft-Windows-Windows Defender/Operational'
$EventIds  = 1116, 1117, 1121, 1122, 1123
$EventNames = @{
    1116 = 'Threat detected'
    1117 = 'Action taken on threat'
    1121 = 'ASR rule blocked an action'
    1122 = 'ASR rule audited an action'
    1123 = 'Controlled Folder Access blocked a change'
}

# Replaces the user name and computer name so the report is safe to share
function Hide-Personal([string]$Text) {
    if ($NoRedact -or -not $Text) { return $Text }
    return $Text.Replace($env:USERNAME, 'labuser').Replace($env:COMPUTERNAME, 'LAB-PC')
}

New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null

# ---------- Collect ----------
$status     = Get-MpComputerStatus
$prefs      = Get-MpPreference
$threats    = @(Get-MpThreat)
$detections = @(Get-MpThreatDetection)
$events     = @(Get-WinEvent -FilterHashtable @{
                    LogName   = $LogName
                    Id        = $EventIds
                    StartTime = (Get-Date).AddDays(-$Days)
                } -ErrorAction SilentlyContinue)

# Look up table so each detection can show a threat name, not only an ID
$threatNames = @{}
foreach ($t in $threats) { $threatNames[[string]$t.ThreatID] = $t.ThreatName }

# ---------- Detections CSV ----------
$detectionRows = foreach ($d in ($detections | Sort-Object InitialDetectionTime)) {
    [pscustomobject]@{
        DetectionTime = $d.InitialDetectionTime
        ThreatID      = $d.ThreatID
        ThreatName    = $threatNames[[string]$d.ThreatID]
        Process       = Hide-Personal $d.ProcessName
        Resources     = Hide-Personal ($d.Resources -join '; ')
        ActionSuccess = $d.ActionSuccess
    }
}
$detectionFile = Join-Path $ReportDir "detections_$Stamp.csv"
if ($detectionRows) { $detectionRows | Export-Csv -Path $detectionFile -NoTypeInformation }

# ---------- Events CSV ----------
$eventRows = foreach ($e in ($events | Sort-Object TimeCreated)) {
    [pscustomobject]@{
        Time      = $e.TimeCreated
        EventID   = $e.Id
        EventType = $EventNames[[int]$e.Id]
        Summary   = Hide-Personal (($e.Message -split "`r?`n")[0])
    }
}
$eventFile = Join-Path $ReportDir "events_$Stamp.csv"
if ($eventRows) { $eventRows | Export-Csv -Path $eventFile -NoTypeInformation }

# ---------- Summary ----------
$activeThreats = @($threats | Where-Object { $_.IsActive }).Count
$asrEnabled    = @($prefs.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 }).Count
$asrTotal      = @($prefs.AttackSurfaceReductionRules_Ids).Count

# Overall verdict: anything here needs a person to look at it
$problems = @()
if (-not $status.RealTimeProtectionEnabled) { $problems += 'Real time protection is OFF' }
if (-not $status.IsTamperProtected)         { $problems += 'Tamper Protection is OFF' }
if ($status.AntivirusSignatureAge -gt 3)    { $problems += "Signatures are $($status.AntivirusSignatureAge) days old" }
if ($status.QuickScanAge -gt 7)             { $problems += 'No quick scan in the last 7 days' }
if ($activeThreats -gt 0)                   { $problems += "$activeThreats active threat(s) not remediated" }
$verdict = if ($problems.Count -eq 0) { 'HEALTHY' } else { 'ATTENTION NEEDED' }

$summary = @()
$summary += 'MICROSOFT DEFENDER HEALTH REPORT'
$summary += "Generated : $(Get-Date -Format 'dd/MM/yyyy HH:mm')"
$summary += "Device    : $(Hide-Personal $env:COMPUTERNAME)"
$summary += "Period    : last $Days day(s)"
$summary += "Overall   : $verdict"
foreach ($p in $problems) { $summary += "            ! $p" }
$summary += ''
$summary += 'PROTECTION STATUS'
$summary += "Real time protection      : $($status.RealTimeProtectionEnabled)"
$summary += "Behaviour monitoring      : $($status.BehaviorMonitorEnabled)"
$summary += "Tamper Protection         : $($status.IsTamperProtected)"
$summary += "PUA protection (1 = on)   : $($prefs.PUAProtection)"
$summary += "Controlled Folder Access  : $($prefs.EnableControlledFolderAccess)"
$summary += "ASR rules in block mode   : $asrEnabled of $asrTotal"
$summary += ''
$summary += 'SIGNATURES AND SCANS'
$summary += "Signature version         : $($status.AntivirusSignatureVersion)"
$summary += "Signature age (days)      : $($status.AntivirusSignatureAge)"
$summary += "Last quick scan           : $(if ($status.QuickScanEndTime) { $status.QuickScanEndTime.ToString('dd/MM/yyyy HH:mm') } else { 'Never' })"
$summary += ''
$summary += 'DETECTIONS AND ACTIONS'
$summary += "Detections recorded       : $($detections.Count)"
$summary += "Distinct threats          : $(@($threats | Select-Object -ExpandProperty ThreatName -Unique).Count)"
$summary += "Active threats            : $activeThreats"
foreach ($id in $EventIds) {
    $count = @($events | Where-Object { $_.Id -eq $id }).Count
    $summary += ("Event {0} {1,-42}: {2}" -f $id, $EventNames[$id], $count)
}

$summaryFile = Join-Path $ReportDir "summary_$Stamp.txt"
$summary | Out-File -FilePath $summaryFile -Encoding utf8

# Show the summary on screen and say where the files are
$summary | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host "Report files saved in $ReportDir"
