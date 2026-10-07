# Detection and Response Recommendations

## Encoded PowerShell

Monitor PowerShell processes using encoded command arguments.

Enable:

- PowerShell Script Block Logging
- Process creation logging
- Sysmon

Investigate encoded PowerShell execution that is not associated with known administrative activity.

## LSASS Process Access

Monitor processes attempting to access `lsass.exe`.

Use endpoint security controls capable of detecting credential dumping.

Enable Windows Credential Guard where supported.

Restrict administrative privileges.

## IIS Child Processes

Monitor `w3wp.exe` spawning command interpreters or scripting engines.

Review:

- IIS logs
- Web application activity
- Parent-child process relationships

Restrict unnecessary execution privileges for IIS application pools.

## Rundll32 Abuse

Monitor unusual `rundll32.exe` command lines.

Pay attention to:

- Script protocols
- Remote URLs
- Unexpected DLL locations
- Suspicious parent processes

## General Recommendations

Centralize Windows telemetry into a SIEM.

Use Sigma rules as portable detection logic and adapt them to the target environment.

Tune detections to reduce false positives while maintaining visibility into suspicious activity.
