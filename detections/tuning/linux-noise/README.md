# Linux Noise Reduction & Signal-to-Noise Tuning
This directory contains documented tuning for Linux-based endpoints within the lab environment. The goal is to isolate security-relevant events from routine system operations.

## Objectives
- **Reduce Alert Fatigue:** Suppress Level 3-5 alerts that represent authorized administrative tasks.
- **Service Profiling:** Define 'Known Good' behavior for system-critical services.
- **Resource Management:** Optimize SIEM processing by silencing high-volume, low-value telemetry at the manager level.

## High-Noise Services Targeted
1. **SSHD:** Filtering repetitive session disconnects from internal vulnerability scanners.
2. **PAM/Sudo:** Suppressing session 'Open/Close' events for automated service accounts.
3. **Cron:** Tuning out execution logs from routine system health and backup scripts.
