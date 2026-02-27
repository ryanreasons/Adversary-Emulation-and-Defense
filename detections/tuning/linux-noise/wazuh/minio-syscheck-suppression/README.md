# MinIO `.minio.sys` syscheck noise suppression (Wazuh)

## What I was seeing
MinIO is busy on purpose. It constantly creates, updates, and deletes internal metadata under `/.minio.sys/`. That is normal for MinIO, but it is absolute chaos for Wazuh File Integrity Monitoring when realtime syscheck is enabled.

My symptom was simple: syscheck alerts were getting spammed by MinIO internals. The signal-to-noise ratio was getting wrecked, and that is exactly how you miss the one file event you actually needed to see.

## What I wanted (the real goal)
I did **not** want to disable File Integrity Monitoring and pretend I solved the problem. I wanted suppression, not blindness.

My target outcome:
- Keep syscheck/FIM running so events still exist in `archives.json`
- Stop generating alert noise for MinIO internals so `alerts.json` stays clean
- Still alert on normal file activity outside `/.minio.sys/`

If the events still exist in `archives.json`, I am still collecting telemetry. If they stop showing up in `alerts.json`, I am controlling noise. That is the balance.

## Environment notes (this matters)
This Wazuh deployment is a Wazuh AIO stack running in Docker on `Dilbert` (10.1.30.101). That means the live rules file is inside the manager container.

- Manager container: `single-node-wazuh.manager-1`
- Live rules path (inside container): `/var/ossec/etc/rules/local_rules.xml`

So when I want GitHub to match production, I export from the container to the host export folder and pull that snapshot into the repo.

## The approach
I chained suppression rules off the stock syscheck rules and only suppressed when `syscheck.path` contains `/.minio.sys/`.

Why I chain instead of doing a generic string rule:
- I am not matching random logs and hoping it is “probably syscheck”
- I only suppress events that already matched the built-in syscheck rules

Base syscheck rule IDs I chained from:
- `550` Integrity checksum changed (modified)
- `553` File deleted
- `554` File added

Local suppression rule IDs I created (unique, no collisions):
- `111550` suppress MinIO modified events (if_sid 550)
- `111553` suppress MinIO deleted events (if_sid 553)
- `111554` suppress MinIO added events (if_sid 554)

Each rule sets `level="0"` and checks `syscheck.path` for `/.minio.sys/`.

## The exact rules (local_rules.xml snippet)
```xml
<!-- Ryan: Suppress noisy MinIO .minio.sys syscheck events for recruiting-memory -->
<rule id="111550" level="0">
  <if_sid>550</if_sid>
  <field name="syscheck.path">/.minio.sys/</field>
  <description>Ryan: Suppress MinIO syscheck noise (modified) where syscheck.path contains '/.minio.sys/'</description>
</rule>

<rule id="111553" level="0">
  <if_sid>553</if_sid>
  <field name="syscheck.path">/.minio.sys/</field>
  <description>Ryan: Suppress MinIO syscheck noise (deleted) where syscheck.path contains '/.minio.sys/'</description>
</rule>

<rule id="111554" level="0">
  <if_sid>554</if_sid>
  <field name="syscheck.path">/.minio.sys/</field>
  <description>Ryan: Suppress MinIO syscheck noise (added) where syscheck.path contains '/.minio.sys/'</description>
</rule>
```

## How I verified it (this is the proof)
Verification date: 2026-02-27

1) MinIO internals still collected
- `archives.json` continued to record lots of `/.minio.sys/` syscheck events
- This proves FIM is still running and collecting telemetry

2) MinIO internals stopped spamming alerts
- `alerts.json` showed **0** `/.minio.sys/` events during the verification window
- This proves suppression is working and noise is controlled

3) Normal activity still alerts
- I created/modified/deleted a test file outside `/.minio.sys/`:
  - `/srv/data/cold/containers/recruiting-memory/budibase/data/minio/ryan-wazuh-test.txt`
- Result: syscheck events appeared in **both** `alerts.json` and `archives.json`

That is the outcome I wanted: MinIO internals suppressed, normal activity still visible.

## Rollback
To undo this, remove the three `11155*` rules from `local_rules.xml`, then restart the Wazuh manager container.
If you do that, `/.minio.sys/` noise will immediately return to `alerts.json`.
