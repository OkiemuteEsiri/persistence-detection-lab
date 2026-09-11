import json
from .models import PersistenceEvent, parse_utc


def load_events(path: str) -> list[PersistenceEvent]:
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    seen = set()
    events = []
    for row in raw:
        event_id = row.get("event_id")
        if event_id in seen:
            raise ValueError(f"duplicate event_id: {event_id}")
        seen.add(event_id)
        events.append(PersistenceEvent(
            event_id=event_id,
            timestamp=parse_utc(row["timestamp"]),
            host=row["host"],
            user=row.get("user", "unknown"),
            event_type=row["event_type"],
            object_name=row["object_name"],
            action=row["action"],
            signer_status=row.get("signer_status", "unknown"),
            parent_process=row.get("parent_process", ""),
        ))
    return events
