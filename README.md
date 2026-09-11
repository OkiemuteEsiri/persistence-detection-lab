# Persistence Detection Lab

Defensive detection-engineering and incident-response project for identifying, prioritizing, investigating, and validating common Windows persistence-related configuration changes using synthetic telemetry.

## Problem Statement
Persistence mechanisms can resemble legitimate administration, software deployment, or operations activity. Effective detection therefore requires more than matching a technique name: telemetry must be validated, context preserved, findings scored transparently, evidence retained, and remediation independently revalidated.

This project demonstrates that workflow without deploying persistence, modifying real systems, or using production/client data.

## Architecture

```text
Synthetic telemetry
      |
      v
Validated immutable models
      |
      v
Fail-closed ingestion + duplicate checks
      |
      v
Persistence detection engine
      |
      +--> context-aware risk scoring
      +--> deterministic finding IDs
      +--> ATT&CK context
      |
      v
Metrics + Markdown reporting
      |
      v
Investigation -> remediation -> revalidation
```

## Detection Coverage

| Control | ATT&CK | Defensive purpose |
|---|---|---|
| Scheduled task creation/modification | T1053.005 | Identify review-worthy scheduled task changes |
| Registry Run Keys / Startup Folder | T1060 | Identify autostart configuration changes |
| Windows service creation/modification | T1543.003 | Identify persistence-relevant service changes |
| Unsigned artifact context | Contextual | Increase analyst priority where trust is weaker |
| Script/command parent context | Contextual | Increase priority for interpreter-driven changes |

ATT&CK mappings provide behavioral context only and are not proof of compromise.

## Repository Structure

```text
.github/workflows/ci.yml        Least-privilege CI
src/models.py                   Immutable validated domain models
src/io.py                       Fail-closed JSON ingestion
src/detector.py                 Detection and scoring engine
src/reporting.py                Executive/analyst Markdown reports
src/cli.py                      Offline CLI
data/synthetic_persistence_events.json
                                Clearly synthetic telemetry
tests/test_detector.py          Unit tests
docs/architecture-methodology.md
                                Architecture, scoring, triage and limitations
reports/example-assessment.md   Example recruiter-facing assessment
```

## Risk Model
The engine applies a mechanism-specific base score and adds bounded context for unsigned artifacts and command/scripting interpreter ancestry. Scores are capped at 100 and mapped to Low, Medium, High, or Critical tiers.

The scoring model is deliberately explainable. It is intended to support triage prioritization, not replace analyst judgment or assert compromise.

## Investigation Workflow
1. Validate the event schema and preserve evidence IDs.
2. Determine whether the persistence-relevant change was authorized.
3. Review initiating identity, process ancestry, signer status, host, and change window.
4. Compare the object with approved software, management, and deployment baselines.
5. Escalate unexplained activity according to the incident-response process.
6. Remove unauthorized mechanisms only through approved remediation procedures.
7. Recollect telemetry and confirm the mechanism is absent or explicitly approved before closure.

## Usage

Run the synthetic dataset through the CLI:

```bash
python -m src.cli data/synthetic_persistence_events.json --output persistence-report.md
```

Run the unit-test suite:

```bash
python -m unittest discover -s tests -v
```

## Example Data
The bundled dataset uses synthetic hostnames, users, object names, and events. It contains no employer, client, credential, malware, payload, or production telemetry.

## Testing
The repository includes 10 unit tests covering:
- scheduled-task detection;
- Run-key/autostart detection;
- service detection;
- negative/benign handling;
- unsigned-artifact scoring;
- command-interpreter context;
- deterministic finding IDs;
- bounded risk scores;
- fleet metrics; and
- explicit investigation caveats in reporting.

GitHub Actions is configured with read-only repository permissions to compile the code and execute the test suite. A committed workflow does not imply a passing run; CI status should be verified independently.

## Skills Demonstrated
- Detection engineering
- Incident-response triage
- ATT&CK-aligned analysis
- Explainable security scoring
- Evidence preservation
- Python data validation
- Defensive telemetry correlation
- Security reporting
- Unit testing
- CI/CD security hygiene
- Remediation and revalidation design

## Limitations
This lab does not execute persistence techniques, create malicious scheduled tasks, alter real registry keys, deploy services, establish persistence, or target live endpoints. It is a defensive analytics project built around synthetic evidence.

The current engine is intentionally compact. A production implementation would typically add platform-specific event schemas, allowlists, change-management integrations, signer/reputation enrichment, endpoint baselines, temporal correlation, analyst dispositions, and SIEM/EDR adapters.

## Roadmap
- Add Sysmon/Windows Event Log adapters for synthetic fixture formats.
- Add approved-baseline and change-window correlation.
- Add host criticality and identity privilege context.
- Add disposition tracking and precision/recall validation fixtures.
- Add Sigma-style detection mappings.
- Add JSON export for downstream dashboards.

## Safety
All examples are defensive and synthetic. Nothing in this repository is intended to establish persistence, evade controls, steal credentials, execute malware, or target systems without authorization.
