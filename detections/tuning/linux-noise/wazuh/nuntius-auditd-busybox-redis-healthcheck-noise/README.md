# Nuntius rule 80792 auditd busybox Redis healthcheck noise

## Status
Deployed to the Alpha Wazuh manager and validated with `wazuh-logtest` plus live post-deployment volume checks.

## Evidence
- **Date:** 2026-05-01
- **Agent:** `Nuntius`
- **Wazuh rule ID:** `80792`
- **Location:** `/var/log/audit/audit.log`
- **Decoder:** `auditd`
- **Audit key:** `audit-wazuh-c`

The last-24-hour review showed `31,435` `/bin/busybox` `80792` events on `Nuntius`.

The Redis healthcheck slice accounted for roughly `15,888` of those events:

- `8,471`: `/bin/sh -c 'redis-cli -a "${REDIS_PASSWORD}" ping | grep -q PONG'`
- `7,417`: `grep -q PONG`

All reviewed events shared the same baseline context:

- `audit.key=audit-wazuh-c`
- `audit.auid=4294967295`
- `success=yes`
- `exit=0`
- `subj=docker-default`
- `audit.exe=/bin/busybox`
- `audit.cwd=/data`

## Assessment
This is noisy baseline activity from a Redis container healthcheck path, not evidence of compromise.

The source healthcheck is doing useful service-health work. Changing the healthcheck risks breaking container health behavior, so the safer control point is a narrow Wazuh child-rule tuning under `80792`.

## What Changed
The deployed rule file is:

```text
/var/ossec/etc/rules/111803_nuntius_auditd_busybox_redis_healthcheck_noise.xml
```

The repo candidate is:

```text
detections/tuning/linux-noise/wazuh/nuntius-auditd-busybox-redis-healthcheck-noise/local_rules.xml
```

Rules added:

- `111803`: suppresses the `/bin/busybox` shell wrapper for `redis-cli ... ping | grep -q PONG`
- `111804`: suppresses the `/bin/busybox` `grep -q PONG` child process

## Why This Was Narrow
The rules require:

- parent rule `80792`
- `audit.key=audit-wazuh-c`
- `audit.auid=4294967295`
- `audit.cwd=/data`
- `audit.exe=/bin/busybox`
- exact decoded command context

For `111803`, Wazuh did not decode `audit.execve.a2` for the shell wrapper sample, so the validated rule matches the exact raw hex-encoded `a2` value for:

```text
redis-cli -a "${REDIS_PASSWORD}" ping | grep -q PONG
```

That keeps the shell-wrapper suppression tied to this Redis healthcheck instead of suppressing every `/bin/busybox sh -c` execution from `/data`.

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

Existing live custom IDs ended at `111802`, so this tuning used `111803` and `111804`.

### `wazuh-analysisd`
`wazuh-analysisd -t` passed before restart.

### `wazuh-logtest`
Positive `wazuh-logtest` validation passed:

- `111803` matched the `/bin/busybox` Redis shell wrapper
- `111804` matched the `/bin/busybox` `grep -q PONG` child process

Negative `wazuh-logtest` validation passed:

- `/bin/busybox` `pg_isready -U infisical -d infisical` stayed on base rule `80792` at level `3`
- `/bin/busybox` Smokeping curl healthcheck stayed on base rule `80792` at level `3`
- `/bin/busybox` `run-parts /etc/periodic/15min` stayed on base rule `80792` at level `3`

### Live Volume Validation
Pre-deployment baseline:

```text
2026-05-01T13:05:58Z
last 10 minutes: 113 busybox Redis-cluster 80792 alerts
last 3 minutes: 34 busybox Redis-cluster 80792 alerts
```

Post-deployment first check:

```text
2026-05-01T13:13:00Z
last 3 minutes: 0 busybox Redis-cluster 80792 alerts
last 5 minutes: 1 busybox Redis-cluster 80792 alert
```

The single last-5-minute hit was inside the restart transition window.

Post-deployment second check:

```text
2026-05-01T13:19:43Z
last 5 minutes: 0 busybox Redis-cluster 80792 alerts
last 3 minutes: 0 busybox Redis-cluster 80792 alerts
```

The second post-deployment check still showed unrelated `80792` activity, including:

- `/usr/bin/env`
- `/bin/busybox`
- `/usr/bin/dash`
- `/usr/bin/curl`
- `/usr/sbin/apparmor_parser`
- `/usr/local/bin/redis-cli`
- `/usr/bin/systemd-detect-virt`
- `/usr/lib/udev/probe-bcache`
- `/usr/bin/run-parts`

That confirms the base `80792` visibility was not broadly disabled.

Recent manager log review showed no duplicate warnings and no references to `111803` or `111804` load problems.

## What Remains Visible
- Any `/bin/busybox` `80792` event that does not match the Redis healthcheck wrapper or `grep -q PONG`
- `/bin/busybox` Postgres healthchecks
- `/bin/busybox` Smokeping curl healthchecks
- `/bin/busybox` run-parts activity
- Interactive user activity because the rules require `audit.auid=4294967295`
- Failed or unusual command variants
- All unrelated root `execve` auditd activity

## Rollback
Remove the deployed rule file and restart Wazuh manager:

```bash
docker exec single-node-wazuh.manager-1 rm -f /var/ossec/etc/rules/111803_nuntius_auditd_busybox_redis_healthcheck_noise.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

## Residual Risk
This tuning reduces the Redis healthcheck slice of `/bin/busybox` `80792` noise. It does not solve all `/bin/busybox` activity on `Nuntius`.

Remaining `80792` families still need separate review, especially:

- `/bin/busybox` Postgres healthchecks
- `/bin/busybox` Smokeping curl healthchecks
- `/usr/bin/env`
- `/usr/bin/dash`
- `/usr/bin/curl`
