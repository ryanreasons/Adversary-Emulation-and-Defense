# Nuntius rule 80792 auditd authentik healthcheck noise

## Status
Deployed to the Alpha Wazuh manager and validated with `wazuh-logtest` plus live post-deployment volume checks.

## Evidence
- **Date:** 2026-05-01
- **Agent:** `Nuntius`
- **Wazuh rule ID:** `80792`
- **Location:** `/var/log/audit/audit.log`
- **Decoder:** `auditd`
- **Audit key:** `audit-wazuh-c`

The last-24-hour review showed `13,959` `authentik`-related `80792` events on `Nuntius`.

The repeated decoded patterns were:

- `/usr/bin/env` running `/lifecycle/ak healthcheck`
- `/usr/bin/bash` running `/lifecycle/ak healthcheck`
- `/usr/bin/mkdir -p /dev/shm//authentik_prometheus_tmp`
- `/usr/bin/cat /dev/shm//authentik-mode`
- `/usr/bin/authentik healthcheck worker`

All reviewed events shared the same context:

- `audit.key=audit-wazuh-c`
- `audit.auid=4294967295`
- `success=yes`
- `exit=0`
- `subj=docker-default`
- `cwd=/`

The hourly pattern was steady at roughly `580` events per hour, which matches repeated container healthcheck behavior.

## Assessment
This is noisy baseline activity from the `authentik` container healthcheck path, not evidence of compromise.

I did not remove or weaken the auditd source rule. The root `execve` audit collection still has value for local evidence. The safer tuning point is Wazuh, using narrow child rules under `80792` that match the decoded `authentik` healthcheck fields.

## What Changed
The deployed rule file is:

```text
/var/ossec/etc/rules/111798_nuntius_auditd_authentik_healthcheck_noise.xml
```

The repo candidate is:

```text
detections/tuning/linux-noise/wazuh/nuntius-auditd-authentik-healthcheck-noise/local_rules.xml
```

Rules added:

- `111798`: suppresses `/usr/bin/env` when it runs `/lifecycle/ak healthcheck`
- `111799`: suppresses `/usr/bin/bash /lifecycle/ak healthcheck`
- `111800`: suppresses `mkdir -p /dev/shm//authentik_prometheus_tmp`
- `111801`: suppresses `cat /dev/shm//authentik-mode`
- `111802`: suppresses `authentik healthcheck worker`

## Why This Was Narrow
The rules require:

- parent rule `80792`
- `audit.key=audit-wazuh-c`
- `audit.auid=4294967295`
- `audit.cwd=/`
- exact executable path
- exact healthcheck argument fields

This avoids suppressing unrelated `80792` activity, interactive user activity, failed execution, and other `authentik` command variants.

## Validation
### Duplicate rule check
Repo XML duplicate check:

```text
NO_DUPLICATES
```

Live Wazuh custom rule duplicate check:

```text
NO_DUPLICATES
```

Existing `Nuntius` auditd custom IDs were `111792` through `111797`, so this tuning used `111798` through `111802`.

### `wazuh-logtest`
Positive `wazuh-logtest` validation passed:

- `111798` matched `/usr/bin/env` running `/lifecycle/ak healthcheck`
- `111799` matched `/usr/bin/bash /lifecycle/ak healthcheck`
- `111800` matched `mkdir -p /dev/shm//authentik_prometheus_tmp`
- `111801` matched `cat /dev/shm//authentik-mode`
- `111802` matched `authentik healthcheck worker`

Negative `wazuh-logtest` validation passed:

- unrelated `curl` healthcheck activity stayed on base rule `80792` at level `3`
- unrelated `busybox` Redis healthcheck activity stayed on base rule `80792` at level `3`

### Live Volume Validation
Pre-deployment baseline:

```text
2026-05-01T06:05:22Z
last 10 minutes: 94 authentik-cluster 80792 alerts
last 3 minutes: 29 authentik-cluster 80792 alerts
```

Post-deployment first check:

```text
2026-05-01T12:27:10Z
last 3 minutes: 0 authentik-cluster 80792 alerts
```

Post-deployment second check:

```text
2026-05-01T12:31:08Z
last 5 minutes: 0 authentik-cluster 80792 alerts
last 3 minutes: 0 authentik-cluster 80792 alerts
```

The second post-deployment check still showed unrelated `80792` activity, including:

- `/bin/busybox`
- `/usr/bin/env`
- `/usr/bin/dash`
- `/usr/bin/curl`
- `/usr/local/bin/redis-cli`
- `/usr/sbin/xtables-nft-multi`
- `/usr/lib/systemd/systemd-executor`
- `/usr/lib/sysstat/sadc`

That confirms the base `80792` visibility was not broadly disabled.

## What Remains Visible
- Any `80792` event that does not match the exact `authentik` healthcheck fields
- Interactive user activity because the rules require `audit.auid=4294967295`
- Failed or unusual command variants
- Other `authentik` execution that does not use the reviewed healthcheck arguments
- All unrelated root `execve` auditd activity

## Rollback
Remove the deployed rule file and restart Wazuh manager:

```bash
docker exec single-node-wazuh.manager-1 rm -f /var/ossec/etc/rules/111798_nuntius_auditd_authentik_healthcheck_noise.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

## Residual Risk
This tuning reduces a known `authentik` healthcheck flood. It does not solve the rest of the `80792` noise on `Nuntius`.

Remaining high-volume `80792` families still need separate review, especially:

- `busybox`
- general `/usr/bin/env`
- `/usr/bin/dash`
- `/usr/bin/curl`
- Redis healthcheck variants
