# Methodology

## 1. Detection Scenario Selection

Detection scenarios were selected based on common Windows attacker behaviors and previous threat hunting observations.

The scenarios include:

- Encoded PowerShell execution
- LSASS process access
- Suspicious IIS child processes
- Rundll32 abuse

## 2. Sigma Rule Development

Each detection was written using the Sigma YAML format.

Rules contain:

- Metadata
- Log source
- Detection selections
- Detection conditions
- False positives
- Severity
- MITRE ATT&CK tags

## 3. Validation

Rules were validated using:

`sigma check`

Validation was used to identify:

- YAML issues
- Invalid conditions
- Invalid MITRE ATT&CK tags
- Sigma best-practice issues

Only rules with zero validation errors and issues were considered complete.

## 4. Splunk Conversion

Validated Sigma rules were converted using the Splunk backend and Windows processing pipeline.

Example:

`sigma convert -t splunk -p splunk_windows`

Generated queries were stored in the `results/` directory.

## 5. False Positive Analysis

Each rule includes possible legitimate activity that may trigger the detection.

Examples include:

- Administrative PowerShell scripts
- Security products accessing LSASS
- IIS maintenance scripts
- Legitimate Rundll32 activity

## 6. MITRE ATT&CK Mapping

Detection rules were mapped to relevant ATT&CK techniques only when supported by the rule behavior.

## 7. Documentation

Each rule and generated Splunk query was retained to demonstrate the full detection engineering workflow.
