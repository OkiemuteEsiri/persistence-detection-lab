# Example Persistence Detection Assessment

> Synthetic lab output for portfolio demonstration. No production telemetry is included.

## Executive Summary
The synthetic dataset produced three persistence-review findings across three hosts. Two findings were elevated by unsigned artifacts and/or command-interpreter context. These observations warrant analyst validation but do not by themselves establish malicious persistence.

## Priority Findings

### LAB-WS-02 — Autostart persistence change
A synthetic Run-key modification was associated with an unsigned artifact and PowerShell parent process. This should be validated against approved software deployment and administrative activity.

### LAB-SRV-01 — Service persistence change
A synthetic service creation event was associated with an unsigned artifact and command-shell parent process. Review the service configuration, signer information, change record, and initiating identity.

### LAB-WS-01 — Scheduled task persistence change
A synthetic scheduled task creation was recorded with trusted signer context. Confirm whether the task matches an approved management or operations workflow.

## Validation Checklist
- Confirm owner and business purpose.
- Confirm approved change/ticket evidence.
- Validate process ancestry and signer context.
- Review adjacent endpoint and identity telemetry.
- Remove unauthorized mechanisms through approved procedures.
- Re-run collection after remediation and confirm no unexplained recurrence.

## ATT&CK Context
- T1053.005 Scheduled Task/Job: Scheduled Task
- T1060 Registry Run Keys / Startup Folder
- T1543.003 Create or Modify System Process: Windows Service

These mappings describe relevant behaviors; they are not proof of adversary activity.
