# First Line Analyst Playbook, Microsoft Defender Alert

The steps to follow when Microsoft Defender raises an alert on a Windows endpoint. Written from what I did in this lab.

## 1. Confirm the Alert

* Check that the machine's clock and time zone are correct, so timestamps can be trusted.
* List detections with `Get-MpThreatDetection` and threats with `Get-MpThreat`.
* Open Protection history in Windows Security for the same alert.

## 2. Collect the Facts

Record these for every alert.

| Question | Where to find it |
|---|---|
| What was detected | Threat name in `Get-MpThreat`, or the rule GUID in the event |
| When | Detection time in the event |
| Which file or process | Resources and ProcessName in `Get-MpThreatDetection`, or Path and Process Name in the event |
| Which user | User field in the event |
| Where it came from | Download URL in the Resources field |
| What Defender did | Event 1117, and IsActive in `Get-MpThreat` |

Useful events in the log Microsoft-Windows-Windows Defender/Operational.

| Event ID | Meaning |
|---|---|
| 1116 | Threat detected |
| 1117 | Action taken on a threat |
| 1121 | Attack surface reduction rule blocked an action |
| 1122 | Attack surface reduction rule audited an action |
| 1123 | Controlled Folder Access blocked a change |

## 3. Decide if It Is Real

* Is the process a genuine Windows or business program, running from its normal folder?
* Does the activity fit what the user or service normally does?
* Did it involve a download, an email attachment or a script from outside?
* For an ASR event, look up the rule GUID in Microsoft's ASR rules reference.

A known program in its normal location doing its normal job points to a false positive. The same file name in a user or temp folder does not.

## 4. Check the Threat Is Dealt With

* Check IsActive in `Get-MpThreat`. A detection does not always mean removal.
* Check that the file is gone from disk.
* If the threat is still active, remove or quarantine it through Protection history, then check again.

## 5. Escalate When Needed

Pass the alert to the second line or incident response team if any of these apply.

* The threat executed, or Defender could not remove it.
* The alert involves credential theft, ransomware behaviour or movement to other machines.
* The same alert appears on more than one machine.
* The source is unknown or the user cannot explain the activity.

## 6. Record and Close

* Write a triage note covering what, when, file and process, action taken, severity, MITRE ATT&CK technique, verdict and next steps.
* For a false positive, note why, and raise an exclusion request if it keeps recurring.
* Attach the evidence, such as screenshots and exported events.
