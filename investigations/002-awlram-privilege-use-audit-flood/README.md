# Investigation: AWL-RAM Wazuh 60107 Privilege Use Audit Flood
**Date:** 2026-04-29
**Analyst:** Ryan Reasons
**Status:** Closed

## Overview
This investigation covers a high-volume Wazuh alert flood on `AWL-RAM` tied to rule `60107`:

- **Wazuh Rule ID:** `60107`
- **Rule Description:** Failed attempt to perform a privileged operation
- **Windows Event ID:** `4673`
- **Provider:** `Microsoft-Windows-Security-Auditing`

This was not malware or compromise evidence. It was excessive Windows Privilege Use auditing on the endpoint. I fixed it at the source by tightening the local audit policy instead of adding a Wazuh suppression rule.

## Evidence
- **Date:** 2026-04-29
- **Agent:** `AWL-RAM`
- **7-day Wazuh count:** roughly `425,527` events
- **Main user:** `reaso`
- **Main privilege:** `SeIncreaseWorkingSetPrivilege`
- **Other privileges seen:** `SeTcbPrivilege`, `SeRestorePrivilege`, `SeLoadDriverPrivilege`, `SeProfileSingleProcessPrivilege`, `SeIncreaseBasePriorityPrivilege`, `SeCreateGlobalPrivilege`, `SeBackupPrivilege`, `SeCreatePermanentPrivilege`

### Major noisy processes
- `firefox.exe`
- `iMazing`
- `Alienware Command Center`
- `Termius`
- `notepad.exe`
- `msedgewebview2.exe`
- `SnippingTool.exe`
- `Windows Package Manager Server`
- `svchost.exe`
- `Thorium`
- `Z-Library`
- `Portals`
- `explorer.exe`
- `Bitwarden`
- `WINWORD.EXE`
- `EXCEL.EXE`
- `Discord`
- `WindowsTerminal.exe`
- `dwm.exe`

The spread across normal desktop applications and background processes pointed to audit policy noise, not one bad process repeatedly doing something suspicious.

## Assessment
- **Classification:** Confirmed noisy baseline
- **Root cause:** Overly broad Privilege Use auditing on `AWL-RAM`
- **Verdict:** Fixed at source

Original policy on the endpoint had all of these set to `Success and Failure`:

- `Non Sensitive Privilege Use`
- `Other Privilege Use Events`
- `Sensitive Privilege Use`

That setting was far too broad for a daily-use Windows system and generated a constant stream of Event ID `4673` activity from normal software.

## Change Made
I changed the local Windows audit policy on `AWL-RAM` to:

- `Non Sensitive Privilege Use: No Auditing`
- `Other Privilege Use Events: No Auditing`
- `Sensitive Privilege Use: Success`

I did not handle this with a Wazuh suppression rule. The noise was coming from the source telemetry, so fixing the audit policy was the safer answer.

## Validation
### Local Windows validation
- Event ID `4673` count in the last 10 minutes after the policy change: `0`

### Wazuh validation
- Rule `60107` count for agent `AWL-RAM` in the last 10 minutes after the policy change: `0`

The post-change checks matched the expected outcome. The flood stopped without suppressing the alert in Wazuh.

## Follow-up
- Keep `Sensitive Privilege Use: Success` enabled so truly sensitive privilege use still has coverage.
- If rule `60107` returns on `AWL-RAM`, re-check local audit policy first before proposing any Wazuh tuning.
- If similar floods appear on other Windows endpoints, review their Privilege Use audit policy before touching Wazuh rules.
