# MinIO `.minio.sys` syscheck noise suppression (Wazuh)

## What I was seeing
MinIO is busy on purpose. It constantly creates, updates, and deletes internal metadata under `/.minio.sys/`. That is normal for MinIO, but it is chaos for Wazuh File Integrity Monitoring when syscheck is enabled.

My symptom was a flood of syscheck alerts for MinIO internals. The signal-to-noise ratio got wrecked, and that is how you miss the one file event you actually needed to see.

## What I wanted (the real goal)
I did **not** want to disable File Integrity Monitoring. I wanted suppression, not blindness.

Target outcome:
- Keep syscheck/FIM running so events still exist in `archives.json`
- Stop generating alert noise for MinIO internals so `alerts.json` stays clean
- Still alert on normal file activity outside `/.minio.sys/`

## The approach
I chained suppression rules off the stock syscheck rules and only suppressed when `syscheck.path` contains `/.minio.sys/`.

Base syscheck rule IDs:
- `550` Integrity checksum changed (modified)
- `553` File deleted
- `554` File added

Local suppression rules:
- `111550` suppress MinIO modified events (if_sid 550)
- `111553` suppress MinIO deleted events (if_sid 553)
- `111554` suppress MinIO added events (if_sid 554)

Each rule sets `level="0"` and checks `syscheck.path` for `/.minio.sys/`.

## Rollback
Remove the three `11155*` rules from `local_rules.xml`, then restart the Wazuh manager container. `/.minio.sys/` noise will return immediately.
