# Windows Defender Lab

## Objective

This lab was about taking a Windows virtual machine with its default security settings and making it stronger using Microsoft Defender. I switched on protections that stop malware and unwanted apps when they are downloaded or run. I wanted to learn the process from start to end and remember the main steps.

## Work Carried Out

1. **Baseline.** I recorded how Defender looked before making any change, so there was something to compare against.
2. **Patching.** I installed the pending Windows and Defender updates and ran the first scan. Updates close known weaknesses that attackers look for, though in a real company they would be tested on a few machines first.
3. **Hardening.** I turned on PUA protection, which blocks unwanted software such as adware, and Controlled Folder Access, which stops untrusted programs from changing files in protected folders. I also added four attack surface reduction rules, which block risky actions such as reading passwords from memory. I ran the rules in audit mode first to check the log for false alarms before switching them to block.
4. **Testing.** I ran four safe tests to check the protections were working.
5. **Investigation.** I checked each alert in the Defender logs and confirmed that every threat had been dealt with.
6. **Automation.** I used a PowerShell script to collect Defender's status, detections and log events into one report with an overall verdict.

## Findings

Before the changes, Defender was running and up to date, but the machine had never been scanned. Some protections were on by default, while others were off or only logging. The machine was partially secure.

| Test | What it checked | Result |
|---|---|---|
| Test virus file (EICAR) | Recognising a known bad file | Blocked and removed in 5 seconds |
| Test script (AMSI) | Catching a script with no file | Blocked before it ran |
| Write into Documents | Ransomware protection | Write refused |
| Test unwanted app (PUA) | PUA protection | Detected, removed by me after 11 minutes |

All four tests were detected. Three were stopped automatically. The unwanted app was detected but left on the disk, so I removed it myself and confirmed it was gone. One more alert came from a normal Windows service and I judged it a false alarm. At the end the report showed the machine as healthy, with no active threats.

![Microsoft Defender events by type](sample-report/events_by_type.png)

## Lessons Learnt

1. Always test the protection yourself and do not just believe it works.
2. Follow a clear order. Take a baseline, agree the basic rules that need to be in place, ask the organisation if it needs anything else, check that legitimate programs are not affected, then harden, test, compare with the baseline and write the report.
3. A detection is not the end of the job. Defender deals with the clear cases, but a person still has to judge the unclear ones and check that each threat was really handled.

## More Detail

| File | Content |
|---|---|
| [triage_notes.md](triage_notes.md) | A note on each of the five alerts |
| [playbook.md](playbook.md) | Steps for a first line analyst when Defender raises an alert |
| [scripts](scripts) | The PowerShell report script and the Python chart script |
| [sample-report](sample-report) | A real report from the lab |
| [screenshots](screenshots) | Evidence for each step |

## Tools

Microsoft Defender Antivirus, PowerShell, Windows Event Viewer, Python, UTM
