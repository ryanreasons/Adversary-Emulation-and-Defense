# Investigation: gens osquery running_processes PostgreSQL Churn

## Situation Overview

This investigation started from the 21-day top-talker review across Wazuh alerts.

- Agent: `gens`
- Agent ID: `003`
- Endpoint IP: `10.1.30.200`
- Source: osquery
- Wazuh rule: `24010`
- Rule description: `osquery: running_processes query result`
- Classification: Source-side osquery tuning candidate

This should not be handled with broad Wazuh suppression. Rule `24010` is generic osquery result telemetry, and suppressing it in Wazuh would hide useful osquery output beyond the noisy process inventory stream.

## Evidence

21-day window reviewed:

`2026-04-11T06:21:10Z` to `2026-05-02T06:21:10Z`

The Linux top offender was:

- Agent: `gens`
- Rule: `24010`
- Description: `osquery: running_processes query result`
- Count: `183,527`
- First observed: `2026-04-19T00:51:22Z`
- Last observed: `2026-05-02T06:19:46Z`

Recent activity showed the stream was still active:

- Last 24h: `16,692`
- Last 6h: `4,312`
- Last 1h: `742`

The osquery action split was nearly even:

- `added`: `91,833`
- `removed`: `91,694`

That means the scheduled query is producing differential process churn, not one static misparsed process.

## Cause

The biggest contributor is PostgreSQL worker/session churn:

- `postgres`: `111,952`
- `/usr/lib/postgresql/16/bin/postgres`: `111,889`

Other repeated process names included:

- `sleep`
- `(udev-worker)`
- `php-fpm`
- `kworker/*`

This points to a broad `running_processes` scheduled query on a busy Linux host. Wazuh is only receiving and alerting on osquery results. The noisy layer is the osquery schedule, not the Wazuh rule.

## Manager-Side Findings

The Wazuh manager shared config does not appear to manage the osquery schedule for `gens`.

Checked files:

- `/var/ossec/etc/shared/default/agent.conf`
- `/var/ossec/etc/shared/interlego/agent.conf`
- `/var/ossec/etc/shared/windows/agent.conf`
- `/var/ossec/etc/ossec.conf`

The manager `ossec.conf` has the osquery wodle disabled on the manager itself. The shared `default/agent.conf` is effectively empty. No centralized `running_processes` schedule was found in Wazuh shared config.

Conclusion: the active `running_processes` schedule is most likely local to `gens`, probably under `/etc/osquery/osquery.conf` or an included osquery pack/config file.

## Endpoint Deployment

Ryan applied the source-side osquery change directly on `gens`.

Endpoint details observed during deployment:

- Hostname: `gens`
- OS: Ubuntu `24.04.4 LTS`
- osquery version: `5.22.1`
- osquery service: `osqueryd.service`
- Config path: `/etc/osquery/osquery.conf`

Original `running_processes` schedule:

```json
"running_processes": {
  "query": "SELECT pid, name, path, cmdline, on_disk FROM processes;",
  "interval": 600
}
```

Final deployed `running_processes` schedule:

```json
"running_processes": {
  "query": "SELECT pid, name, path, cmdline, on_disk FROM processes;",
  "interval": 300,
  "removed": false
}
```

There was one temporary JSON syntax issue during deployment because the comma after `"interval": 300` was missing. osquery logged the parse failure at `2026-05-02 06:56:36 UTC`. The config was corrected before final restart and validation.

## Source-Side Change

Do not suppress Wazuh rule `24010` broadly.

Deployed change on `gens`:

- Keep the `running_processes` query.
- Set `removed: false` so osquery stops logging removal churn for short-lived PostgreSQL/session processes.
- Do not exclude all `postgres` rows unless the reduced schedule still produces unacceptable volume.

This preserves new process visibility while cutting the least useful half of the differential stream.

Deployed osquery schedule fragment:

```json
{
  "schedule": {
    "running_processes": {
      "query": "SELECT pid, name, path, cmdline, on_disk FROM processes;",
      "interval": 300,
      "removed": false
    }
  }
}
```

The interval was changed from `600` to `300` during the endpoint edit. That does not reduce cadence. The meaningful noise-reduction control in this pass is `"removed": false`. If `running_processes` remains too noisy after the removal churn is fixed, the next safer source-side step is to raise the interval back to `600` or higher, or narrow the SQL query, before considering any Wazuh-side tuning.

## Endpoint Commands To Run On gens

Discovery:

```bash
hostname
sudo systemctl status osqueryd --no-pager
sudo osqueryi --version
sudo find /etc/osquery -maxdepth 3 -type f -print
sudo grep -RIn '"running_processes"\\|"schedule"\\|"interval"\\|"removed"' /etc/osquery
sudo sed -n '1,220p' /etc/osquery/osquery.conf
```

Backup:

```bash
sudo cp -a /etc/osquery/osquery.conf "/etc/osquery/osquery.conf.bak.$(date -u +%Y%m%dT%H%M%SZ)"
```

Validation before restart:

```bash
sudo rm -rf /tmp/osquery-configcheck.db
sudo osqueryd --config_path=/etc/osquery/osquery.conf --database_path=/tmp/osquery-configcheck.db --config_check
sudo rm -rf /tmp/osquery-configcheck.db
```

Restart after config change:

```bash
sudo systemctl restart osqueryd
sudo systemctl status osqueryd --no-pager
```

Local result check:

```bash
sudo tail -n 100 /var/log/osquery/osqueryd.results.log | grep '"name":"running_processes"' || true
```

## Validation Results

Endpoint config validation:

- `python3 -m json.tool /etc/osquery/osquery.conf`: `JSON_OK`
- `osqueryd --config_check` with a temporary database path: passed
- `osqueryd.service` restarted cleanly at `2026-05-02 07:20:00 UTC`
- Post-restart journal showed no config parse errors

Local osquery evidence:

- The post-restart `running_processes` batch at `2026-05-02 07:23:15 UTC` showed `action:"added"` events.
- No `action:"removed"` events were observed in that post-restart batch.

Wazuh manager validation window:

- Restart point: `2026-05-02T07:20:00Z`
- Validation query time: `2026-05-02T07:30:05Z`
- Agent: `gens`
- Rule: `24010`
- Query name: `running_processes`

Pre-fix comparison window:

- Window: `2026-05-02T06:50:00Z` to `2026-05-02T07:20:00Z`
- Total `running_processes` events: `128`
- `added`: `66`
- `removed`: `62`

Post-fix validation window:

- Window: `2026-05-02T07:20:00Z` to `2026-05-02T07:30:05Z`
- Total `running_processes` events: `113`
- `added`: `113`
- `removed`: `0`

Other osquery results still arrived after the endpoint change:

- `systemd_units`: `6`
- `listening_ports`: `4`
- `logged_in_users`: `2`

Validation conclusion:

- Targeted `removed` churn dropped from `62` events in the pre-fix 30-minute window to `0` after restart.
- `running_processes` `added` telemetry remained visible.
- Other osquery query results remained visible.
- This confirms the source-side change reduced removal churn without disabling osquery ingestion or broadly suppressing Wazuh rule `24010`.

## Final Decision

This is a source-side osquery schedule issue, not a Wazuh XML issue.

Status: Source-side change deployed and live validated.

Residual risk:

- The `added` side of `running_processes` remains visible and still produced `113` events in the first post-restart validation window.
- Some of that immediate post-restart volume may be osquery re-baselining after service restart.
- If rule `24010` remains a top offender after this change settles, continue tuning at the osquery source by adjusting interval or query scope. Do not suppress rule `24010` broadly in Wazuh.

Rollback:

```bash
sudo cp -a /etc/osquery/osquery.conf.bak.<timestamp> /etc/osquery/osquery.conf
sudo python3 -m json.tool /etc/osquery/osquery.conf >/dev/null
sudo rm -rf /tmp/osquery-configcheck.db
sudo osqueryd --config_path=/etc/osquery/osquery.conf --database_path=/tmp/osquery-configcheck.db --config_check
sudo rm -rf /tmp/osquery-configcheck.db
sudo systemctl restart osqueryd
sudo systemctl status osqueryd --no-pager -l
```

## References

- osquery configuration supports per-query `interval`, `removed`, and `snapshot` settings: https://osquery.readthedocs.io/en/latest/deployment/configuration/
