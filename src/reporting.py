from .detector import metrics


def markdown_report(findings) -> str:
    m = metrics(findings)
    lines = [
        "# Persistence Detection Assessment",
        "",
        "> Synthetic defensive analysis. Findings are signals for investigation, not proof of compromise.",
        "",
        "## Executive Metrics",
        f"- Total findings: {m['total_findings']}",
        f"- Critical/High: {m['critical_high']}",
        f"- Highest score: {m['highest_score']}",
        f"- Affected hosts: {m['affected_hosts']}",
        "",
        "## Findings",
    ]
    for f in sorted(findings, key=lambda x: x.score, reverse=True):
        lines += [
            f"### {f.finding_id} — {f.title}",
            f"- Host: {f.host}",
            f"- Severity: {f.severity}",
            f"- Confidence: {f.confidence}",
            f"- Score: {f.score}/100",
            f"- ATT&CK: {', '.join(f.attack_techniques)}",
            f"- Evidence: {', '.join(f.evidence_ids)}",
            f"- Rationale: {f.rationale}",
            f"- Remediation: {f.remediation}",
            f"- Revalidation: {f.revalidation}",
            "",
        ]
    return "\n".join(lines)
