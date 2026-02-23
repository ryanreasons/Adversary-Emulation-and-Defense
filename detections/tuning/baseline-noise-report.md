# SIEM Fatigue Analysis: The 500k Event Challenge
**Date:** 2026-02-23
**Total Events Analyzed:** ~780,000 (30-day window)

## The 'Big Three' Noise Makers
My audit revealed that three specific Rule IDs account for over 90% of the total log volume. By targeting these for surgical tuning, I will reach my 70% fatigue reduction goal almost immediately.

| Rule ID | Count | Functional Category | Analysis |
|---------|-------|---------------------|----------|
| 67027   | 478,524 | Network/Firewall | High-volume connection permit/deny noise. |
| 60104   | 141,647 | Windows Endpoint | Process creation telemetry (High-volume). |
| 60107   | 102,119 | Windows Endpoint | Process termination telemetry. |

## Strategy
I will not silence these globally. I will identify the specific routine processes (e.g., monitoring agents, system health checks) causing these spikes and create Level 0 child rules for those specific signatures.
