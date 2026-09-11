# Architecture and Methodology

## Purpose
This project demonstrates defensive detection engineering for common Windows persistence-related configuration changes using synthetic telemetry only.

## Architecture
1. `src/models.py` validates immutable telemetry and finding objects.
2. `src/io.py` performs fail-closed JSON ingestion and duplicate-ID checks.
3. `src/detector.py` applies explainable persistence detections and bounded scoring.
4. `src/reporting.py` creates executive and analyst-readable Markdown output.
5. `src/cli.py` provides an offline analysis workflow.

## Detection Scope
The current controls identify suspicious or review-worthy changes involving:
- Scheduled tasks — ATT&CK T1053.005.
- Registry Run Keys / Startup Folder — ATT&CK T1060.
- Windows services — ATT&CK T1543.003.

ATT&CK mappings provide behavioral context only. A mapping does not prove malicious activity or compromise.

## Risk Method
A base score is assigned by persistence mechanism. Context raises risk when the associated artifact is unsigned or when the change originates from a command/scripting interpreter. Scores are capped at 100 and converted into Low, Medium, High, or Critical tiers.

## Investigation Workflow
1. Validate whether the change was authorized.
2. Confirm the initiating identity, host, process lineage, and change window.
3. Compare the object to approved software, deployment, and administration baselines.
4. Escalate unexplained changes according to incident-response procedure.
5. Remove unauthorized persistence only through approved containment/remediation processes.
6. Recollect telemetry and confirm the mechanism is absent or explicitly approved before closure.

## Limitations
This lab does not execute persistence techniques, deploy payloads, modify real hosts, or perform live response. It intentionally focuses on telemetry validation, detection logic, triage, remediation, and revalidation.
