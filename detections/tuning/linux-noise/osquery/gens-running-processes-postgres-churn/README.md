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

## Access Status

SSH reachability from Ryan's Windows host to `gens` works:

- `10.1.30.200:22`: open

The current temporary `codex` key is not authorized on `gens`:

- `codex@10.1.30.200`: `Permission denied (publickey)`

The Wazuh VM could not reach `gens` over SSH:

- `alpha -> 10.1.30.200:22`: closed or filtered

Because of that, no endpoint-side osquery change was deployed during this pass.

## Recommended Source-Side Change

Do not suppress Wazuh rule `24010` broadly.

Preferred first change on `gens`:

- Keep the `running_processes` query.
- Increase the interval if it is currently aggressive.
- Set `removed: false` so osquery stops logging removal churn for short-lived PostgreSQL/session processes.
- Do not exclude all `postgres` rows unless the reduced schedule still produces unacceptable volume.

This preserves new process visibility while cutting the least useful half of the differential stream.

Candidate osquery schedule fragment:

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

Do not blindly replace the whole osquery config with this fragment. Merge this into the existing `running_processes` scheduled query after confirming the current query and interval.

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
sudo osqueryd --config_path=/etc/osquery/osquery.conf --config_check
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

## Wazuh Validation Plan

After the endpoint config is changed and osqueryd is restarted, validate from the Wazuh manager:

- Compare `gens` rule `24010` `running_processes` volume before and after.
- Confirm other osquery query names still arrive.
- Confirm Wazuh rule `24010` itself is still visible for non-noisy osquery results.

Expected result if `removed: false` is accepted:

- `removed` events for `running_processes` should drop to `0`.
- Overall `running_processes` volume should drop significantly.
- `added` events should remain visible.

## Final Decision

This is a source-side osquery schedule issue, not a Wazuh XML issue.

Status: Endpoint change pending SSH access to `gens`.

## References

- osquery configuration supports per-query `interval`, `removed`, and `snapshot` settings: https://osquery.readthedocs.io/en/latest/deployment/configuration/
