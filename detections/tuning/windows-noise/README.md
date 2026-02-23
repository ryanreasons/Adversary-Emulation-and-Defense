# Windows Event ID Tuning & Suppression
This repository tracks custom rules created to handle the high-volume event logs inherent to Windows environments.

## Methodology
Tuning follows a 'Top-Talker' analysis. I identify the most frequent alerts in the SIEM dashboard and determine the root cause. If the activity is an authorized system process, a child rule is implemented with a Level 0 (Silent) status to ensure only actionable threats reach the SOC.

## Key Targets
- **Security Event ID 4624/4634:** Optimizing Logon/Logoff noise while preserving visibility into lateral movement.
- **Security Event ID 4672:** Managing noise from special privileges assigned to routine service account logons.
- **System Event ID 7045:** Filtering routine service installations from verified software updates.
