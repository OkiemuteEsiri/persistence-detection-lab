from dataclasses import dataclass
from datetime import datetime, timezone


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class PersistenceEvent:
    event_id: str
    timestamp: datetime
    host: str
    user: str
    event_type: str
    object_name: str
    action: str
    signer_status: str = "unknown"
    parent_process: str = ""

    def __post_init__(self):
        if not self.event_id or not self.host or not self.event_type or not self.object_name:
            raise ValueError("event_id, host, event_type and object_name are required")
        if self.action not in {"create", "modify", "delete", "execute"}:
            raise ValueError("invalid action")
        if self.signer_status not in {"trusted", "unsigned", "unknown"}:
            raise ValueError("invalid signer_status")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")


@dataclass(frozen=True)
class Finding:
    finding_id: str
    host: str
    severity: str
    confidence: str
    score: int
    title: str
    rationale: str
    evidence_ids: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    remediation: str
    revalidation: str
