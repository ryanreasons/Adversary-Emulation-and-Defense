# Investigation: AWL-RAM GitHub CLI Helper Process Noise

## Situation Overview

This investigation started from the active top offender after the historical `60107` privilege-use flood was confirmed closed.

- Agent: `AWL-RAM`
- Source event: Windows Security Event ID `4688`
- Wazuh rule: `67027`
- Rule description: `A process was created.`
- Classification: Confirmed noisy baseline, narrowly tuned

Rule `67027` is useful process creation telemetry, so broad suppression is not acceptable. The tuning target is only GitHub CLI helper process churn that repeats during normal repo and CLI activity.

## Evidence

The last 72-hour rollup showed `AWL-RAM` rule `67027` as the highest still-active offender:

- 72h count: `39,021`
- 24h count: `10,542`
- 6h count: `3,505`
- 1h count: `1,209`
- 15m count: `349`

The one-hour breakdown showed mixed process creation activity. Most of it should remain visible.

The narrow GitHub CLI helper pairs were:

- `C:\Program Files\GitHub CLI\gh.exe` launching `C:\Windows\System32\tzutil.exe`
- `C:\Program Files\GitHub CLI\gh.exe` launching `C:\Windows\System32\conhost.exe`

Wazuh stores these decoded EventChannel path fields with doubled backslash characters, so the deployed PCRE2 rules intentionally match `C:\\Program Files\\GitHub CLI\\gh.exe` style field values.

Observed sample fields:

- `win.system.computer`: `AWL-RAM`
- `win.eventdata.subjectUserName`: `reaso`
- `win.eventdata.parentProcessName`: `C:\Program Files\GitHub CLI\gh.exe`
- `win.eventdata.newProcessName`: `C:\Windows\System32\tzutil.exe`
- `win.eventdata.newProcessName`: `C:\Windows\System32\conhost.exe`

## Assessment

This is normal GitHub CLI helper activity on Ryan's workstation. The activity is not suspicious by itself. It becomes a tuning candidate because it repeatedly fires generic process creation alerts while not adding useful detection value in this specific parent-child context.

This is not a recommendation to suppress `4688` globally. That would blind useful process creation visibility.

## Candidate Rule Scope

Candidate file:

`detections/tuning/windows-noise/wazuh/awlram-github-cli-helper-process-noise/local_rules.xml`

Deployed manager path:

`/var/ossec/etc/rules/111805_awlram_github_cli_helper_process_noise.xml`

Rule IDs:

- `111805`: suppresses only `gh.exe -> tzutil.exe` on `AWL-RAM` for user `reaso`
- `111806`: suppresses only `gh.exe -> conhost.exe` on `AWL-RAM` for user `reaso`

## What Remains Visible

The following remain visible under the normal Windows process creation rules:

- Any `67027` event from another endpoint
- Any `67027` event from another user
- Any `gh.exe` child process other than `tzutil.exe` or `conhost.exe`
- Any Codex, Git, PowerShell, Firefox, Docker, Wazuh agent, or Windows service process creation event
- Any suspicious process creation chain involving GitHub CLI that does not exactly match this known helper pattern

## Validation Notes

Live Wazuh alerts confirmed the target events were firing base rule `67027` before the candidate was written.

`wazuh-logtest` with reconstructed alert JSON can decode the fields, but it does not enter the `windows_eventchannel` parent rule path because raw Windows archives are not enabled. Because of that, the meaningful validation path is:

- Confirm duplicate rule IDs before deploy
- Validate XML/ruleset syntax with `wazuh-analysisd -t`
- Deploy the rule file
- Restart Wazuh manager
- Run live volume validation against target and non-target `67027` events

## Deployment Validation

Duplicate rule ID check before deployment showed the live custom rules ended at `111804`. The new rules use `111805` and `111806`.

The first deployed regex used normal single-backslash Windows path matching. Live validation showed the target pairs still leaking through as base `67027`, so that version was not accepted as complete.

The corrected version matches Wazuh's doubled-backslash EventChannel field representation.

Pre-deploy live target volume:

- Last 5m: `51` target alerts
- Last 3m: `34` target alerts

Corrected post-deploy live validation:

- Last 5m: `0` target alerts, `52` other `67027` alerts still visible
- Last 3m: `0` target alerts, `48` other `67027` alerts still visible

This confirmed the tuning is narrow. The GitHub CLI helper noise stopped, while unrelated process creation telemetry stayed visible.

Status: Deployed and live validated.
