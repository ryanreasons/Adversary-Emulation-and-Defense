# Rule Tuning: Metasploit Database Noise
**Target Rule**: 67027  
**Process**: postgres.exe  
**Reduction Goal**: ~350,000 hits/month

## Methodology
In a laboratory environment where Metasploit is active, the underlying PostgreSQL database generates massive "Process Created" telemetry as it forks workers.

## Implementation Logic
I implemented a Regex-based filter to match the process name at the end of the path string. This ensures that even if the Metasploit installation directory changes, the tuning remains effective.

```xml
<rule id="100067" level="0">
  <if_sid>67027</if_sid>
  <field name="win.eventdata.newProcessName" type="pcre2">postgres\.exe$</field>
</rule>
