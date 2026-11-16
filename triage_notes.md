# Triage Notes

Five alerts raised on the lab machine on 16 November 2026. Four came from safe test files and one was a real audit event from normal Windows activity. Each was investigated through `Get-MpThreatDetection`, `Get-MpThreat` and the Defender Operational event log.

## Summary

| No. | Time | Alert | Source | Action by Defender | Verdict |
|---|---|---|---|---|---|
| 1 | 15:23 | LSASS access by svchost.exe | ASR rule, audit (1122) | None, audit only | False positive |
| 2 | 15:37 | EICAR test file in a zip download | Antivirus (1116, 1117) | Blocked and removed in 5 seconds | True positive (test) |
| 3 | 15:41 | AMSI test string in PowerShell | AMSI (1116, 1117) | Script blocked before it ran | True positive (test) |
| 4 | 15:42 | PowerShell writing to Documents | Controlled Folder Access (1123) | Write blocked | True positive (test) |
| 5 | 15:48 | AMTSO PUA test file | PUA protection (1116, 1117) | Detected, not removed until I acted | True positive (test) |

Event counts for the session: 8 detection events (1116), 7 action events (1117), 1 ASR audit event (1122), 1 Controlled Folder Access block (1123). No ASR block events (1121) were raised, because none of the tests matched an ASR rule.

## Alert 1, LSASS Access (False Positive)

| Field | Detail |
|---|---|
| Detected | 16/11/2026 15:23:22, event 1122 |
| Rule | Block credential stealing from LSASS (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2), audit mode |
| Process | C:\Windows\System32\svchost.exe running the SysMain service |
| Target | C:\Windows\System32\lsass.exe |
| User | NT AUTHORITY\SYSTEM |
| Action | None, audit only |
| Severity | Low |
| MITRE ATT&CK | T1003.001, OS Credential Dumping, LSASS Memory (the technique the rule guards against) |

**Analysis.** SysMain is a built in Windows service that manages memory. It ran from the genuine System32 folder as SYSTEM, at startup, with no user activity or download involved. This is normal behaviour that happens to match the rule.

**Verdict and next steps.** False positive. No exclusion needed. The rule was moved to block mode, where it denies the access without affecting the service. The same file name running from a user or temp folder would need a full investigation.

## Alert 2, EICAR Test File

| Field | Detail |
|---|---|
| Detected | 16/11/2026 15:37:09 and 15:37:26, event 1116 |
| Threat | Tool:Win32/EICAR_Test_File |
| File | Temporary download file (.crdownload) in the Downloads folder |
| Source | https://secure.eicar.org/eicar_com.zip, downloaded in Microsoft Edge |
| Action | Blocked and removed, event 1117 at 15:37:14 and 15:37:31 |
| Severity | Severe (Defender rating) |
| MITRE ATT&CK | T1204.002, User Execution, Malicious File |

**Analysis.** Defender scanned the download while it was still in progress and found the test file inside the zip. Edge reported the download as blocked and Windows Security raised an alert. The threat did not execute and is no longer active. Two detections were logged because the file was downloaded twice.

**Verdict and next steps.** True positive on a harmless test file. In a real case I would check where the link came from, whether other users received it and whether the file reached any other machine.

## Alert 3, AMSI Test String

| Field | Detail |
|---|---|
| Detected | 16/11/2026 15:41:28 and 15:41:46, each with a paired record 5 seconds later, event 1116 |
| Threat | Virus:Win32/MpTest!amsi |
| Process | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| File | None, the content was in memory |
| Action | Script blocked, event 1117 at 15:41:43 and 15:41:59 |
| Severity | Severe (Defender rating) |
| MITRE ATT&CK | T1059.001, Command and Scripting Interpreter, PowerShell |

**Analysis.** Microsoft's AMSI test string was typed into PowerShell. Defender inspected it through AMSI before it ran and PowerShell returned "This script contains malicious content and has been blocked by your antivirus software". No file was involved, which shows detection of script content that never touches the disk. Each run produced a second record with no process or resource, which I read as a follow up record for the same event.

**Verdict and next steps.** True positive on a test string. In a real case I would find out who ran the script, where it came from and what the full command was.

## Alert 4, Controlled Folder Access Block

| Field | Detail |
|---|---|
| Detected | 16/11/2026 15:42:51, event 1123 |
| Process | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| Target | %userprofile%\Documents\ |
| User | Local user account |
| Action | Write blocked, no file created |
| Severity | Medium |
| MITRE ATT&CK | T1486, Data Encrypted for Impact |

**Analysis.** A PowerShell command tried to create a file in Documents, a protected folder. Controlled Folder Access blocked it and `Test-Path` confirmed the file did not exist. PowerShell only reported "Could not find file", so the real cause was visible only in the Defender log and in Protection history.

**Verdict and next steps.** True positive, the protection worked as designed. A user who reports that an app cannot save files may be hitting this control, so the Defender log is the first place to check. A trusted app can be allowed through the allowed apps list.

## Alert 5, Potentially Unwanted App

| Field | Detail |
|---|---|
| Detected | 16/11/2026 15:48:02 and 15:48:18, event 1116 |
| Threat | PUA:AndroidOS/Amtso.A!MTB |
| File | com.amtso.mobiletestfilepua.apk, two copies in the Downloads folder |
| Source | amtso.eicar.org, the AMTSO Android PUA test file, downloaded in Microsoft Edge |
| Action | Detected only. Removed by me through Protection history, event 1117 at 15:59:21 |
| Severity | Low |
| MITRE ATT&CK | T1204.002, User Execution, Malicious File (closest match) |

**Analysis.** PUA protection detected the file, but unlike the EICAR and AMSI alerts it was not removed automatically. Both copies stayed in Downloads and `Get-MpThreat` showed the threat as active. I removed it through Protection history, then confirmed that the folder was empty and the threat was no longer active. Time from detection to removal was about 11 minutes.

**Verdict and next steps.** True positive on a test file. The lesson is that a detection does not always mean the threat was cleaned up, so the status of every alert needs checking.
