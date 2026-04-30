# AGENTS.md

## Scope

This folder contains Wazuh tuning artifacts for Linux alert noise.

## Rules

- Treat XML files here as candidate or exported Wazuh rule artifacts.
- Do not assume these files are live in production.
- Always check for duplicate Wazuh rule IDs before adding or modifying rules.
- Prefer narrow matches using specific paths, agents, audit commands, executable paths, containers, or service names.
- Do not suppress broad auditd, syscheck, Docker, PAM, sudo, authentication, or kernel alert families without explicit approval.
- For Docker or container-runtime noise, prove the exact command, executable, user, and host before proposing a suppression.
- Keep README files evidence-based.
- Mark tuning as proposed until Ryan validates it in the live Wazuh manager.