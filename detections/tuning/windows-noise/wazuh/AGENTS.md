# AGENTS.md

## Scope

This folder contains Wazuh tuning artifacts for Windows alert noise.

## Rules

- Treat XML files here as candidate or exported Wazuh rule artifacts.
- Do not assume these files are live in production.
- Always check for duplicate Wazuh rule IDs before adding or modifying rules.
- Do not suppress an entire Wazuh rule when a narrower field match is possible.
- Prefer matching on specific combinations such as:
  - `rule.id`
  - `agent.name`
  - Windows event ID
  - process path
  - privilege name
  - username
  - parent process
  - command line
- Avoid broad matches on generic strings like `cmd.exe`, `powershell.exe`, `svchost.exe`, or `chrome.exe` unless there is additional narrowing context.
- Keep README files evidence-based.
- Mark tuning as proposed until Ryan validates it in the live Wazuh manager.