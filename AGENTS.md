# AGENTS.md

## Repository purpose

This repository stores detection engineering, Wazuh tuning, investigation notes, and security lab documentation for Ryan Reasons' homelab and blue-team practice.

## General working rules

- Do not push directly to `main`.
- Do not delete evidence, investigation notes, sample logs, or existing tuning history unless explicitly instructed.
- Keep changes small, reviewable, and scoped to the requested task.
- Prefer creating or updating files under the existing repository structure instead of inventing a new layout.
- Before editing Wazuh rules, inspect existing XML files for duplicate rule IDs.
- Never create a Wazuh tuning rule that broadly suppresses an entire rule family unless explicitly approved.
- Prefer narrow suppression logic tied to specific rule IDs, event IDs, fields, paths, users, agents, process names, or known-noisy application behavior.
- Documentation should only describe a tuning change as complete after Ryan has validated it against the live Wazuh environment.

## Wazuh tuning rules

- Production Wazuh runs as Docker AIO on Alpha.
- Live Wazuh rule files are inside the `single-node-wazuh.manager-1` container, not directly on the VM host filesystem.
- Repo files are candidates and documentation, not proof that production is changed.
- Treat `wazuh-logtest`, Wazuh manager restart logs, and post-change alert counts as the source of truth.
- Do not assume a rule works just because the XML looks correct.
- Check for duplicate `<rule id="">` values before proposing a change.
- Do not reuse existing rule IDs.
- Do not suppress entire Windows process creation, PowerShell, Defender, Sysmon, WMI, Task Scheduler, service creation, or authentication categories.

## Documentation style

Write in Ryan's style:
- Direct, grounded, and practical.
- Use first-person comments when writing commands or workflow notes.
- Avoid overly polished corporate language.
- Explain why the change was made, what evidence supported it, and how it was validated.
- Avoid em dashes.
- Do not include AI usage acknowledgments unless explicitly requested.

## Command style

When writing commands:
- Use copy-pasteable command blocks.
- Prefer `tee` blocks or scripted file writes instead of manual editing.
- Do not use `set -euo pipefail`.
- Keep command blocks under 120 lines.
- For Windows, use PowerShell-friendly commands.
- For Linux server commands, include clear comments before the action.

## Wazuh investigation workflow

For each heavy-hitter tuning case, use this structure:

1. Evidence
   - Date range
   - Rule ID
   - Agent
   - Hit count
   - Top fields such as process, path, privilege, event ID, user, or command

2. Assessment
   - Confirmed noisy baseline
   - Confirmed abnormal
   - Unresolved
   - Needs more samples

3. Proposed change
   - What exact field pattern should be tuned
   - What should not be suppressed

4. Validation required
   - `wazuh-logtest` if applicable
   - Wazuh manager reload/restart check if production rule changes are made
   - Post-change alert count check

5. Documentation
   - Only write final documentation after Ryan confirms production validation.