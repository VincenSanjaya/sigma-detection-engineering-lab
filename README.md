# Sigma Detection Engineering Lab

Blue Team detection engineering project focused on writing, validating, and converting Sigma detection rules for suspicious Windows activity.

The project uses Sigma CLI on macOS and converts detection logic into Splunk-compatible queries.

## Objectives

- Learn Sigma rule structure
- Build reusable detection rules
- Validate detection logic
- Map detections to MITRE ATT&CK
- Convert Sigma rules into Splunk queries
- Document false positives and detection assumptions

## Tools Used

- Sigma CLI
- pySigma
- Splunk backend
- macOS Terminal
- Visual Studio Code

## Detection Rules

### 1. Suspicious Encoded PowerShell

Detects PowerShell execution using encoded command arguments such as:

- `-enc`
- `-EncodedCommand`

MITRE ATT&CK:

- T1059.001 - PowerShell
- T1027 - Obfuscated/Compressed Files and Information

### 2. Suspicious LSASS Process Access

Detects non-system processes accessing:

`lsass.exe`

This behavior may indicate credential dumping.

MITRE ATT&CK:

- T1003.001 - LSASS Memory

### 3. Suspicious IIS Child Process

Detects `w3wp.exe` spawning suspicious command or scripting processes such as:

- cmd.exe
- powershell.exe
- pwsh.exe
- rundll32.exe
- mshta.exe
- wscript.exe
- cscript.exe

This behavior may indicate web shell execution or exploitation of an IIS application.

### 4. Suspicious Rundll32 Execution

Detects suspicious `rundll32.exe` command-line patterns including:

- JavaScript execution
- VBScript execution
- HTTP or HTTPS references
- Control_RunDLL usage

MITRE ATT&CK:

- T1218.011 - Rundll32

## Workflow

Detection Idea

↓

Sigma Rule

↓

Sigma Validation

↓

MITRE ATT&CK Mapping

↓

Splunk Conversion

↓

Detection Documentation

## Repository Structure

`rules/`

Contains custom Sigma detection rules.

`results/`

Contains Splunk queries generated from Sigma rules.

`reports/`

Contains detection engineering documentation.

`screenshots/`

Contains validation and conversion evidence.

## Example

Sigma rule:

`rules/suspicious-encoded-powershell.yml`

Generated Splunk query:

`Image IN ("*\\powershell.exe", "*\\pwsh.exe") CommandLine IN ("* -enc *", "* -EncodedCommand *")`

## Skills Demonstrated

- Detection engineering
- Sigma rule development
- Windows process monitoring
- MITRE ATT&CK mapping
- SIEM query generation
- Splunk detection logic
- False positive analysis
- Blue Team methodology

## Disclaimer

This project was created for educational and defensive security purposes.# sigma-detection-engineering-lab
