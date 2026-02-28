# Wazuh Rule Tuning - Suppress auditd ANOM_PROMISCUOUS prom=256 for veth* on scout only

## Goal
I had noisy alerts from ANOM_PROMISCUOUS on scout when temporary veth interfaces toggled promiscuous mode.
I kept telemetry (archives) but suppressed alerts for this harmless container case.

## Environment
- Wazuh version: 4.14.2
- Manager container: single-node-wazuh.manager-1
- Rules file: /var/ossec/etc/rules/local_rules.xml
- Agent: scout (10.1.30.116)
- Base rule SID: 80710

## Implemented Rule (local_rules.xml)

    <group name="ryan_tuning,scout,linux">
      <rule id="990710" level="0">
        <if_sid>80710</if_sid>
        <hostname>scout</hostname>
        <field name="audit.dev">^veth</field>
        <description>Ryan: Suppress auditd ANOM_PROMISCUOUS prom=256 for veth* on scout only</description>
      </rule>
    </group>

## Validation

Example audit line from scout:

    type=ANOM_PROMISCUOUS msg=audit(1772261382.978:8964): dev=vethsr0 prom=256 old_prom=0 ...

Expected behavior:
- alerts.json contains no matches for the token
- archives.json may still contain the token

Observed behavior:
- alerts.json: PASS
- archives.json: PASS

Result:
Noise eliminated for veth* promiscuous toggles on scout while preserving telemetry.


