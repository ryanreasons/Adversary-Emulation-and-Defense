# Nuntius rule 80792 auditd container runtime noise

## Status
Validated with `wazuh-logtest`, pending live-volume monitoring.

## Evidence
- **Date:** 2026-04-30
- **Agent:** `Nuntius`
- **Wazuh rule ID:** `80792`
- **Location:** `/var/log/audit/audit.log`
- **Decoder:** `auditd`
- **Audit key:** `audit-wazuh-c`

Description examples:
- `Audit: Command: /usr/bin/runc.`
- `Audit: Command: /usr/libexec/docker/docker-init.`
- `Audit: Command: /usr/sbin/xtables-nft-multi.`
- `Audit: Command: /var/lib/rancher/k3s/.../bin/ipset.`
- `Audit: Command: /usr/local/bin/pg_isready.`
- `Audit: Command: /usr/local/bin/redis-cli.`

Active auditd source rules on Nuntius include root `execve` collection:

```text
-a always,exit -F arch=b64 -S execve -F euid=0 -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -F euid=0 -k audit-wazuh-c
```

Nuntius is running Docker, k3s, and containerd, so a chunk of this traffic is expected container-runtime behavior.

## Assessment
This looks like noisy baseline activity from container runtime helpers and health checks, not proof of compromise.

I do not want to remove the auditd source rules yet. Those root `execve` rules still have value for raw local evidence when something actually matters. The safer move here is to keep the audit source in place and suppress only the specific Wazuh alerts that are repeatedly hitting for known container-runtime paths and contexts.

## Why level 0 in Wazuh instead of removing auditd rules
If I remove the auditd rules, I lose the raw local audit trail for root `execve` activity. That is too blunt.

Using narrow `level="0"` child rules under `80792` lets me:
- keep the local audit evidence
- keep the broader root `execve` coverage
- stop alert noise for a short list of known container-runtime commands
- leave unrelated `80792` activity visible

Raw auditd collection remains enabled on `Nuntius`.

## What changed after validation
My first candidate used raw `<match>` clauses against the audit text. That version failed in `wazuh-logtest` because Wazuh had already decoded the auditd fields and the raw string matches did not fire the way I needed.

The validated version uses decoded fields that `wazuh-logtest` proved were present for these events:
- `audit.key`
- `audit.auid`
- `audit.exe`
- `audit.cwd`
- `audit.execve.a3`

## Candidate suppression scope
This candidate `local_rules.xml` adds narrow child rules for:

- `111792`: `/usr/bin/runc` or `/runc` when `audit.key=audit-wazuh-c` and `audit.auid=4294967295`
- `111793`: `/usr/libexec/docker/docker-init` when `audit.key=audit-wazuh-c` and `audit.auid=4294967295`
- `111794`: `/usr/sbin/xtables-nft-multi` when `cwd="/var/lib/rancher/k3s/server"`
- `111795`: `/var/lib/rancher/k3s/.../bin/ipset` when `cwd="/var/lib/rancher/k3s/server"`
- `111796`: `/usr/local/bin/pg_isready` when `audit.key=audit-wazuh-c` and `audit.auid=4294967295`
- `111797`: `/usr/local/bin/redis-cli` when `audit.key=audit-wazuh-c`, `audit.auid=4294967295`, and `audit.execve.a3=ping`

## What is suppressed
- Known `runc` exec noise tied to the root `execve` audit rule
- Known `docker-init` exec noise tied to the root `execve` audit rule
- Known k3s helper activity for `xtables-nft-multi`
- Known k3s helper activity for `ipset`
- Known container health-check style activity for `pg_isready`
- Known container health-check style activity for `redis-cli`

## What intentionally remains visible
- `sudo`
- Docker CLI activity by user `ryan`
- `grep`
- `bash`
- `dash`
- `env`
- `curl`
- `diff`
- Any other `80792` event that does not match the narrow command and context checks above

## Validation
Positive `wazuh-logtest` validation passed for:
- `111792`
- `111793`
- `111794`
- `111795`
- `111796`
- `111797`

Negative `wazuh-logtest` validation passed for these commands staying on base rule `80792` at level `3`:
- `bash`
- `curl`
- `dash`
- `env`

Production Wazuh rule file was loaded as:

```text
/var/ossec/etc/rules/111792_nuntius_auditd_container_runtime_noise.xml
```

Production manager location:
- Alpha Wazuh manager container

## Post-deployment live check
After loading the validated rules, a 15-minute query still showed targeted commands. That window likely included transition time or backlog, so it was not a clean read on steady-state behavior.

A tighter last-3-minutes live query showed `161` remaining rule `80792` events. Remaining descriptions were:
- `/bin/busybox`: `61`
- `/usr/bin/env`: `42`
- `/usr/bin/curl`: `17`
- `/usr/bin/dash`: `17`
- `/usr/bin/authentik`: `6`
- `/usr/bin/bash`: `6`
- `/usr/bin/cat`: `6`
- `/usr/bin/mkdir`: `6`

The targeted tuned commands were no longer present in the last-3-minutes `80792` results:
- `/usr/bin/runc`
- `/runc`
- `/usr/libexec/docker/docker-init`
- `/usr/sbin/xtables-nft-multi`
- `/usr/local/bin/pg_isready`
- `/usr/local/bin/redis-cli`
- k3s `ipset`

That is a good spot check for the tuned cases. It does not mean `80792` noise is fully solved on `Nuntius`. Unrelated auditd command noise still remains and may need later investigation.

## Validation Ryan still needs to run
1. Keep watching post-deployment alert counts for `Nuntius` to confirm the reduction holds outside a short spot-check window.
2. Confirm unrelated `80792` activity still shows up after the rule load.
3. Check that raw audit evidence still remains available locally and, where expected, in Wazuh archives.
4. Re-check Docker CLI by user `ryan`, `grep`, `sudo`, and other unsuppressed commands with live samples if they start showing up heavily.

## Final status
Validated with `wazuh-logtest` and confirmed with a live 3-minute post-deployment spot check. Unrelated `80792` noise still remains and may need future tuning.
