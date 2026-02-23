# Tuning Philosophy: The Level 0 Principle
In this project, I prioritize **Signal Fidelity** over **Log Suppression**.

## Silent (Level 0) vs. Agent-Disabled
When tuning noisy events like Rule 67027 (Process Creation) or 60104 (Audit Failure), I implement Level 0 child rules rather than disabling the log source at the endpoint.

### Why?
1. **Forensic Integrity:** Should an incident occur, the 'silent' logs remain in the Elasticsearch index for retroactive hunting and root-cause analysis.
2. **Correlation:** Maintaining a stream of 'Known Good' telemetry allows for better correlation with 'Known Bad' events.
3. **Analyst Efficiency:** The goal of this repo is to reach a 70% reduction in *actionable alerts*, not to create blind spots in our data lake.
