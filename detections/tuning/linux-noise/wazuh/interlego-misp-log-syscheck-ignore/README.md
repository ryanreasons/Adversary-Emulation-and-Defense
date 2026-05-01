# Interlego MISP log syscheck ignore

## Status
Deployed through Wazuh centralized agent configuration and validated with live post-change checks.

## Evidence
- **Date:** 2026-05-01
- **Agent:** `interlego`
- **Agent ID:** `011`
- **Wazuh rule ID:** `550`
- **Alert type:** Syscheck integrity checksum changed
- **Location:** `syscheck`

The last-24-hour review showed high-volume `550` events from MISP application log files:

- `/srv/compose/misp/logs/debug.log`
- `/srv/compose/misp/logs/misp-workers.log`

Observed counts:

- `34`: `/srv/compose/misp/logs/debug.log`
- `30`: `/srv/compose/misp/logs/misp-workers.log`

These were application log files changing under normal MISP runtime behavior.

## Assessment
This is source telemetry noise, not something that should be handled with a Wazuh alert suppression rule.

FIM checksum monitoring on actively written application log files has low detection value and creates repeated rule `550` alerts. The safer fix is to ignore the MISP logs path in syscheck for `interlego` only.

I did not suppress rule `550` broadly. I did not ignore MISP config files.

## What Changed
Created a dedicated Wazuh centralized config group:

```text
interlego
```

Assigned agent `011` to:

```text
default, interlego
```

Deployed this centralized agent config:

```xml
<agent_config>
  <syscheck>
    <ignore>/srv/compose/misp/logs</ignore>
  </syscheck>
</agent_config>
```

The repo copy is:

```text
detections/tuning/linux-noise/wazuh/interlego-misp-log-syscheck-ignore/agent.conf
```

The live manager path is:

```text
/var/ossec/etc/shared/interlego/agent.conf
```

## Why This Was Narrow
The change is scoped to the `interlego` Wazuh group and agent `011`.

It ignores:

- `/srv/compose/misp/logs`

It does not ignore:

- `/srv/compose/misp/configs/config.php`
- `/srv/compose/misp/configs/database.php`
- `/srv/compose/misp/configs/email.php`
- other MISP files
- other Linux agents in the `default` group

The MISP config changes seen during the same review remain visible and should be investigated separately if they continue.

## Validation
### Group and sync validation
`interlego` was active as agent `011`.

Before the change, `interlego` belonged to:

```text
default
```

After the change, `interlego` belonged to:

```text
default, interlego
```

Wazuh reported:

```text
Agent '011' is synchronized.
```

Agent `011` was restarted from the manager with:

```text
/var/ossec/bin/agent_control -R -u 011
```

After restart, the agent remained active and syscheck restarted.

### Live volume validation
Pre-change live window was quiet for this exact path:

```text
2026-05-01T14:41:38Z
last 10 minutes: 0 MISP log rule 550 alerts
last 3 minutes: 0 MISP log rule 550 alerts
```

Post-change check:

```text
2026-05-01T14:53:24Z
last 5 minutes: 0 MISP log rule 550 alerts
last 10 minutes: 0 MISP log rule 550 alerts
```

Other `interlego` rule `550` activity remained visible in the post-change 10-minute window, including Wazuh shared config files such as:

- `/var/ossec/etc/shared/merged.mg`
- `/var/ossec/etc/shared/agent.conf`
- `/var/ossec/etc/shared/cis_debian_linux_rcl.txt`
- `/var/ossec/etc/shared/ar.conf`

That confirms the change did not broadly disable rule `550` for `interlego`.

## What Remains Visible
- MISP config files under `/srv/compose/misp/configs`
- Other MISP paths outside `/srv/compose/misp/logs`
- Other `interlego` syscheck events
- Rule `550` for all other agents

## Rollback
Remove the `interlego` group assignment or remove the centralized ignore, then restart agent `011`.

Remove the agent from the dedicated group:

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_groups -r -i 011 -g interlego -q
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -R -u 011
```

Or remove the group config:

```bash
docker exec single-node-wazuh.manager-1 rm -f /var/ossec/etc/shared/interlego/agent.conf
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -R -u 011
```

## Residual Risk
This does not resolve the MISP config-file changes seen during the rule `550` review. Those remain visible and should not be tuned without separate investigation.

This also does not solve Windows scheduled-task rule `550` churn on `PC` and `AWL-RAM`. Those paths overlap with persistence behavior and need their own endpoint-side review before any tuning.
