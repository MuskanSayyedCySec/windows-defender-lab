# Windows Defender Lab

A hands on lab where I patch, harden and monitor a Windows 11 machine with Microsoft Defender, trigger safe test alerts, investigate them through the event logs and automate a health report in PowerShell.

I built this to learn how endpoint protection is run day to day in a security team, and to practise the patching, hardening and alert triage work that entry level analyst roles involve.

## Status

In progress. This page is updated as each stage is finished.

| Stage | Status |
|---|---|
| Lab setup | Done |
| Baseline and patching | Done |
| Hardening | Done |
| Safe detection tests | In progress |
| Alert investigation and triage notes | To do |
| First line analyst playbook | To do |
| Automated health report (PowerShell) | To do |

## Lab Setup

| Item | Detail |
|---|---|
| Host | MacBook Air, Apple silicon |
| Virtualisation | UTM |
| Guest | Windows 11 Pro, Arm64, 8 GB RAM, 64 GB disk |
| Account | Local account, no Microsoft account |
| Rollback | A clean clone of the VM taken before any change |

Everything runs inside the virtual machine, so the host is never exposed to test files and the lab can be reset at any time.

## Baseline and Patching

I recorded the state of the machine with `Get-MpComputerStatus` before changing anything, then patched it and recorded it again.

| Item | Before | After |
|---|---|---|
| Real time protection | On | On |
| Behaviour monitoring | On | On |
| Tamper Protection | On | On |
| Signature version | 1.463.315.0 | 1.463.317.0 |
| Signature age | 0 days | 0 days |
| Quick scan | Never run | Completed, age 0 days |
| Windows quality updates | Pending | 3 installed (2 security, 1 critical) |
| Driver updates | Pending | 1 installed |
| Defender engine | Not recorded | 1.1.26110.3 |
| Defender platform | Not recorded | 4.18.26100.4 |

**Main finding.** Protection was on and signatures were current, but the machine had never been scanned. `QuickScanAge` showed 4294967295, the largest value the field can hold, which Defender uses to mean no scan on record. After `Start-MpScan -ScanType QuickScan` it dropped to 0.

## Hardening

Several Defender protections are off or only partly on by default. I checked each one with `Get-MpPreference`, changed it with `Set-MpPreference`, then checked again.

| Protection | Before | After |
|---|---|---|
| Potentially unwanted app (PUA) protection | Audit only | Block |
| Controlled Folder Access (ransomware protection) | Off | On |
| Cloud delivered protection | On | On |
| Automatic sample submission | On | On |
| Tamper Protection | On | On |
| Attack surface reduction rules | None | 4 rules added |

### Attack Surface Reduction Rules

Rule IDs are taken from Microsoft's attack surface reduction rules reference.

| Rule | GUID | Mode |
|---|---|---|
| Block credential stealing from LSASS | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 | Audit |
| Use advanced protection against ransomware | c1db55ab-c21a-4637-bb3f-a12568109d35 | Audit |
| Block execution of potentially obfuscated scripts | 5beb7efe-fd9a-4556-801d-275e5ffc04cc | Audit |
| Block process creations from PSExec and WMI commands | d1e49aac-8f56-4280-b9ba-993a6d77406c | Audit |

I added the rules in audit mode first. Audit mode logs what a rule would have blocked (event 1122) without stopping it, so false positives can be found and excluded before the rule is enforced. The next step is to review the audit events and move the rules to block mode.

## Problems and What I Learnt

* **Signature update failed on the first try.** `Update-MpSignature` returned "The remote procedure call failed" (0x800706be). Windows was updating the Defender engine in the background at the time. After Windows Update finished, the same command worked and the signature version moved from 1.463.315.0 to 1.463.317.0.
* **Check more than one source.** The Windows Update page showed one update waiting, while `Get-HotFix` listed five. The Update history page settled it, since Windows had installed most updates in the background before I looked.
* **Confirm the clock before trusting timestamps.** Some updates were dated a day ahead, so I checked the time zone and system time with `Get-TimeZone` and `Get-Date`. Both were correct. I could not explain the date difference, so I rely on the Update history page for install dates.
* **A strange number can be a placeholder.** 4294967295 was not a real scan age. It meant never scanned.

## Evidence

Screenshots are in the `screenshots` folder.

| File | Shows |
|---|---|
| 01_clean_snapshot.png | Clean clone of the VM before changes |
| 02_baseline_before.png | Defender status before patching |
| 03_signature_update_error.png | Signature update error |
| 04_updates_pending.png | Windows Update installing the pending update |
| 05_updates_done.png | Windows Update up to date |
| 05b_update_history.png | Update history |
| 06_patched_and_scanned.png | Updates, signature version and first scan |
| 07_hardening_before.png | Defender settings before hardening |
| 08_pua_cfa_enabled.png | PUA protection and Controlled Folder Access on |
| 09_asr_audit.png | Four ASR rules in audit mode |
| 10_windows_security_settings.png | Cloud protection and Tamper Protection on |

## Tools

Microsoft Defender Antivirus, PowerShell, Windows Update, Windows Event Viewer, UTM
