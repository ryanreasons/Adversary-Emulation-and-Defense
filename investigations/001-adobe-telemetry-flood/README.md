# Investigation: High-Volume Process Creation (Adobe)
**Date**: 2026-02-23  
**Analyst**: Ryan Reasons  
**Status**: Resolved (Tuned)

## Event Summary
The SIEM was observed receiving over 100,000 alerts per month regarding "Process Creation" (Rule 67027) originating from a Windows endpoint.

## Technical Analysis
Analysis of the raw JSON telemetry revealed that the process "CRWindowsClientService.exe" (Adobe Photoshop Express) was spawning repeatedly. This was identified as routine crash reporting/telemetry and not a security threat.

## Remediation
Implemented a Level 0 (Silent) child rule in "local_rules.xml" on the Wazuh Manager (Dilbert) to suppress these specific alerts while maintaining global visibility into other process creations.
