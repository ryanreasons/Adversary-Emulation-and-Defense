# Investigation 001 - Adobe telemetry flood (CRWindowsClientService.exe) - Wazuh tuning

## What happened
My Windows endpoint started generating noisy process creation telemetry around `CRWindowsClientService.exe`. It was not actionable in my environment, but it was loud enough to drown out real signals and waste time during triage.

This investigation documents the tuning I put in place so the noise stops, while normal Windows process creation detection remains intact.

## Root cause (practical)
The endpoint was repeatedly emitting process creation activity tied to Adobe’s `CRWindowsClientService.exe` (commonly observed with Adobe tooling or related components). Wazuh was correctly seeing the activity, but in my environment it was operational noise.

So the correct move here was tuning, not “disabling detection.”

## Final solution (what is deployed)
Two Wazuh rules exist and they must NOT share an ID.

1) A **high-signal detection rule** that matches Windows Security Event ID `4688` when the process name ends in `CRWindowsClientService.exe`.
   - File: `detections/tuning/windows-noise/wazuh/100067-crwindowsclientservice.xml`
   - Rule ID: `100067`

2) A **local suppression rule** that reduces alerting for the noisy pattern by targeting the parent/related SID and matching the process name string.
   - File: `detections/tuning/windows-noise/wazuh/local_rules.xml`
   - Rule ID: `110067`

Important detail: Wazuh will warn and behave unpredictably if rule IDs collide. Duplicate rule IDs trigger warnings like:
`Rule ID '100067' is duplicated. Only the first occurrence will be considered.`

The fix was to keep the detection rule as `100067` and move the suppression rule to `110067`.

## Why the suppression rule is safe
The suppression rule is tightly scoped:
- It only triggers when the event contains `CRWindowsClientService.exe`
- It is tied to the specific detection SID (`67027`) it was flooding
- It does NOT shut off general 4688 monitoring or other process creation visibility

This is what I want in a real SOC workflow: reduce junk without blinding myself.

## Validation steps (manager-side)
On the Wazuh manager (containerized on Dilbert), I validated this in two ways:

1) Confirm the live rules do not contain duplicate IDs:
- `100067` should only exist once in the live rules paths
- `110067` should exist in the local rules file

2) Confirm logtest behaves correctly:
- The detection rule still fires for a sample `4688` event with `CRWindowsClientService.exe`
- No duplicated-rule warning appears during runtime after restart

## Export / repo sync workflow
I export the deployed rules from the Wazuh manager container to the Dilbert host, then copy them to this repo so GitHub matches production.

This prevents “documentation drift” where the repo is stale but production is different.

## Files related to this investigation
- `detections/tuning/windows-noise/wazuh/100067-crwindowsclientservice.xml`
- `detections/tuning/windows-noise/wazuh/local_rules.xml`

## Closure criteria
This investigation is “done” when:
- Wazuh manager shows no duplicate rule ID warnings for `100067`
- My endpoint stops flooding alerts for this pattern
- Other process creation alerts remain normal and actionable
