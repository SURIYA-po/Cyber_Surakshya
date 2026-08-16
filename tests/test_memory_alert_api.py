from datetime import datetime, timezone

# Moved out of app.py into the API layer's read-model module when app.py was
# split into routers. Importing it no longer drags in the whole application.
from api.projections import build_alerts_from_memory_records
from memory.models import MemoryRecord


def test_build_alerts_from_memory_records_uses_detection_content():
    record = MemoryRecord(
        backend="qdrant_sqlite",
        collection="detections",
        record_type="detection_result",
        entity_id="10.0.0.5",
        content={
            "detection_id": "det-123",
            "predicted_label": "DDoS",
            "confidence": 0.97,
            "status": "malicious",
        },
        metadata={"severity": "CRITICAL"},
        created_at=datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc),
    )

    alerts = build_alerts_from_memory_records([record])

    assert len(alerts) == 1
    assert alerts[0]["id"] == "det-123"
    assert alerts[0]["attack_type"] == "DDoS"
    assert alerts[0]["severity"] == "CRITICAL"
    assert alerts[0]["status"] == "Investigating"
    # The memory primary key travels alongside the detection id, so
    # DELETE /alerts/{id} can address the stored record rather than a
    # list entry that no longer exists.
    assert alerts[0]["record_id"] == record.record_id
