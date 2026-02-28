# Scout syscheck noise reduction (Prometheus + Loki + Promtail)

## What I was seeing
Scout runs Prometheus, Loki, and Promtail. Those stacks create, rotate, delete, and compact files constantly. That behavior is expected, but Wazuh File Integrity Monitoring treats it like a never-ending incident.

The symptom was a flood of syscheck alerts:
- `550` Integrity checksum changed
- `553` File deleted
- `554` File added

Most of it was not security signal. It was normal churn in data directories.

## What I wanted (the real goal)
I did not want to disable syscheck globally. I wanted targeted noise reduction.

My target outcome:
- Keep syscheck enabled for real paths that matter (`/etc`, binaries, configs, scripts)
- Stop alert spam from high-churn observability data directories on Scout
- Preserve signal-to-noise so real file changes stand out

## The fix
On Scout (agent-side), I added syscheck ignores for the following paths **inside the `<syscheck>` section**:

- `/srv/data/scout/prometheus`
- `/srv/data/scout/loki`
- `/srv/data/scout/promtail`

This is agent-side tuning, not a manager rule suppression. The agent simply stops generating syscheck events for those directories.

## Proof it worked
Wazuh agent logs confirmed:
- syscheck explicitly printed “Ignore 'file' entry …” for the three paths
- manager-side verification showed Scout syscheck alerts for 550/553/554 dropped to **0** in the last hour

That is exactly the outcome I wanted: telemetry stays strong where it matters, and the high-churn data paths stop poisoning alerts.

## Files in this folder
- `ossec.conf.scout` = the authoritative Scout agent config snapshot pulled from production
- `syscheck.block.xml` = just the `<syscheck>` block extracted for easy review
