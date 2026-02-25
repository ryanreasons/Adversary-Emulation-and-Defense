# Investigation 001 – Adobe CRWindowsClientService Telemetry Flood

## Situation Overview

This investigation started because Windows Security 4688 process creation events were flooding Wazuh. The executable responsible was CRWindowsClientService.exe, part of Adobe Photoshop Express crash telemetry handling.

The activity itself was not malicious. The issue was alert fatigue and signal degradation inside the SIEM. When noise increases, meaningful detection decreases. That is not acceptable in a detection stack.

The objective was suppression of this specific rule being fired.

---

## Root Cause

Two architectural problems were identified.

First, a custom detection rule (100067) was created to detect CRWindowsClientService.exe execution.

Second, a suppression rule in local_rules.xml was mistakenly assigned the same rule ID (100067).

Wazuh only loads the first instance of a duplicated rule ID. Everything after that becomes undefined behavior. The manager correctly generated warning 7612 indicating rule duplication.


---

## Final Detection Architecture

### High-Fidelity Detection Rule

File:
detections/tuning/windows-noise/wazuh/100067-crwindowsclientservice.xml

- Rule ID: 100067
- Level: 10
- Matches Windows Security Event ID 4688
- Uses PCRE2 pattern:
  (?i)\\CRWindowsClientService\.exe$

This rule explicitly detects execution of the Adobe crash service binary.

---

### Targeted Suppression Rule

File:
detections/tuning/windows-noise/wazuh/local_rules.xml

- Rule ID: 110067
- Level: 0
- Uses <if_sid>67027</if_sid>
- Matches:
  CRWindowsClientService\.exe

This suppresses only the generic 67027 process creation alert when the executable is Adobe crash telemetry.

All other 4688 detections remain intact and still firing. 

This preserves detection integrity while eliminating operational noise.

---

## Validation Process

- Confirmed rule load order via ossec.conf ruleset section
- Removed duplicated rule IDs
- Moved rule backups outside live rules directory
- Restarted Wazuh manager cleanly
- Verified no new 7612 duplicate warnings in ossec.log
- Replayed test event using wazuh-logtest
- Confirmed detection rule fires correctly
- Confirmed suppression rule behaves as designed
- Exported final production rules from container
- Synced repository to deployed state
- Enforced LF line endings via .gitattributes

No assumptions. All verified.

---

## Final State

- Duplicate rule ID issue fully resolved
- Detection rule stable and active
- Suppression rule isolated and controlled
- Production and Git repository synchronized
- Investigation formally documented

This was not just noise cleanup. This was an extensive first rule fine-tuning learning lesson in the attempt to create proper rule hygiene and lifecycle management.

Status: Closed
