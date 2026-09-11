import hashlib
from collections import defaultdict
from .models import PersistenceEvent, Finding

ATTACK = {
    "scheduled_task": ("T1053.005", "Scheduled Task/Job: Scheduled Task"),
    "run_key": ("T1060", "Registry Run Keys / Startup Folder"),
    "service": ("T1543.003", "Create or Modify System Process: Windows Service"),
    "startup": ("T1060", "Registry Run Keys / Startup Folder"),
}


def _finding_id(host: str, title: str, evidence: tuple[str, ...]) -> str:
    raw = f"{host}|{title}|{'|'.join(sorted(evidence))}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _severity(score: int) -> str:
    if score >= 85: return "Critical"
    if score >= 70: return "High"
    if score >= 45: return "Medium"
    return "Low"


def detect(events: list[PersistenceEvent]) -> list[Finding]:
    by_host: dict[str, list[PersistenceEvent]] = defaultdict(list)
    for event in events:
        by_host[event.host].append(event)

    findings: list[Finding] = []
    for host, host_events in by_host.items():
        for event in sorted(host_events, key=lambda e: e.timestamp):
            score = 0
            title = ""
            techniques: tuple[str, ...] = ()
            rationale = []

            if event.event_type == "scheduled_task" and event.action in {"create", "modify"}:
                score, title = 65, "Scheduled task persistence change"
                techniques = ("T1053.005",)
                rationale.append("A scheduled task was created or modified.")
            elif event.event_type in {"run_key", "startup"} and event.action in {"create", "modify"}:
                score, title = 70, "Autostart persistence change"
                techniques = ("T1060",)
                rationale.append("An autostart location was changed.")
            elif event.event_type == "service" and event.action in {"create", "modify"}:
                score, title = 68, "Service persistence change"
                techniques = ("T1543.003",)
                rationale.append("A service configuration was created or modified.")
            else:
                continue

            if event.signer_status == "unsigned":
                score += 12
                rationale.append("Associated binary or script is unsigned.")
            if event.parent_process and event.parent_process.lower() in {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"}:
                score += 8
                rationale.append("Change was initiated by a command or script interpreter.")

            score = min(score, 100)
            evidence = (event.event_id,)
            findings.append(Finding(
                finding_id=_finding_id(host, title, evidence), host=host,
                severity=_severity(score), confidence="Medium", score=score,
                title=title, rationale=" ".join(rationale), evidence_ids=evidence,
                attack_techniques=techniques,
                remediation="Review authorization, remove unauthorized persistence, and validate the affected host using approved IR procedures.",
                revalidation="Recollect telemetry and confirm the persistence mechanism is absent or explicitly approved."
            ))
    return findings


def metrics(findings: list[Finding]) -> dict:
    severities = {s: 0 for s in ("Critical", "High", "Medium", "Low")}
    for finding in findings:
        severities[finding.severity] += 1
    return {
        "total_findings": len(findings),
        "critical_high": severities["Critical"] + severities["High"],
        "highest_score": max((f.score for f in findings), default=0),
        "affected_hosts": len({f.host for f in findings}),
        "by_severity": severities,
    }
