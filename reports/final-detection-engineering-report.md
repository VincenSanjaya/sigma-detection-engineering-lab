# Final Detection Engineering Report

## Project Overview

This project focused on building and validating Sigma detection rules for suspicious Windows activity.

The goal was to practice a practical detection engineering workflow:

Detection idea

↓

Sigma rule development

↓

Rule validation

↓

MITRE ATT&CK mapping

↓

Splunk query conversion

↓

Documentation and tuning considerations

The lab was performed on macOS using Sigma CLI and the Splunk backend.

## Tools Used

- Sigma CLI
- pySigma
- Splunk backend
- macOS Terminal
- Visual Studio Code

## Detection Summary

### Detection 1 - Suspicious Encoded PowerShell

This rule detects PowerShell execution using encoded command arguments such as:

`-enc`

and:

`-EncodedCommand`

These arguments may be used to hide malicious or suspicious PowerShell content.

MITRE ATT&CK:

- T1059.001 - PowerShell
- T1027 - Obfuscated/Compressed Files and Information

Generated Splunk query:

`Image IN ("*\\powershell.exe", "*\\pwsh.exe") CommandLine IN ("* -enc *", "* -EncodedCommand *")`

### Detection 2 - Suspicious LSASS Process Access

This rule detects non-system processes accessing:

`lsass.exe`

LSASS contains sensitive authentication material and is a common target for credential dumping.

MITRE ATT&CK:

- T1003.001 - LSASS Memory

Generated Splunk query:

`TargetImage="*\\lsass.exe" NOT (SourceImage IN ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*"))`

### Detection 3 - Suspicious IIS Child Process

This rule detects the IIS worker process:

`w3wp.exe`

spawning suspicious child processes such as:

- cmd.exe
- powershell.exe
- pwsh.exe
- rundll32.exe
- mshta.exe
- wscript.exe
- cscript.exe

This behavior may indicate web shell execution, exploitation, or post-exploitation activity.

Generated Splunk query:

`ParentImage="*\\w3wp.exe" Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe", "*\\rundll32.exe", "*\\mshta.exe", "*\\wscript.exe", "*\\cscript.exe")`

### Detection 4 - Suspicious Rundll32 Execution

This rule detects suspicious Rundll32 execution patterns involving:

- JavaScript
- VBScript
- HTTP references
- HTTPS references
- Control_RunDLL

Rundll32 is a legitimate Windows binary that may be abused for proxy execution.

MITRE ATT&CK:

- T1218.011 - Rundll32

## Validation

Each Sigma rule was validated using:

`sigma check`

Completed rules returned:

`0 errors`

`0 condition errors`

`0 issues`

Validation was also used to identify and correct invalid MITRE ATT&CK tagging.

## Splunk Conversion

Validated rules were converted using:

`sigma convert -t splunk -p splunk_windows`

The generated Splunk queries were stored inside:

`results/`

This demonstrates how Sigma can be used as portable detection logic and converted into SIEM-specific queries.

## False Positive Considerations

Detection engineering requires balancing visibility and false positives.

Possible false positives identified during this project include:

- Legitimate encoded PowerShell administration
- Security software accessing LSASS
- IIS applications launching command-line utilities
- Legitimate Rundll32 activity

Each rule should be tuned based on the target environment before being used in production.

## Key Lessons

This project demonstrated that detection engineering is not only about writing rules.

A useful detection also requires:

- Correct telemetry
- Accurate detection logic
- MITRE ATT&CK context
- False positive awareness
- SIEM compatibility
- Continuous tuning

## Skills Demonstrated

- Sigma rule development
- Detection engineering
- Windows process monitoring
- MITRE ATT&CK mapping
- Splunk query generation
- Detection validation
- False positive analysis
- Blue Team methodology

## Limitations

The project focused on rule development and query generation.

The detections were not deployed into a production Splunk environment.

Further testing with real Windows telemetry would be required before production use.

## Conclusion

This project demonstrated an end-to-end detection engineering workflow using Sigma.

Four custom detection rules were created, validated, mapped to MITRE ATT&CK, and converted into Splunk-compatible detection queries.

The lab strengthened practical skills relevant to SOC analysis, threat hunting, SIEM engineering, and defensive security.