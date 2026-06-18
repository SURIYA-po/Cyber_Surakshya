# IDS Detection Adapter

The IDS Detection Adapter is the bridge between the existing IDS inference
pipeline and the platform `DetectionResult` schema.

```text
Raw flow data
-> inference.py artifact loading, preprocessing, prediction
-> DetectionResult
```

## Scope

This component only adapts one raw flow record into one validated
`DetectionResult`. It does not implement a Detection Agent, LangGraph workflow,
Coordinator Agent, Analysis Agent, Decision Agent, Response Agent, or memory
system.

## Files

```text
adapters/
  detection/
    base.py          # Common detector adapter interface
    ids_adapter.py   # Existing IDS inference -> DetectionResult bridge

tests/
  adapters/
    test_ids_adapter.py
```

## Usage

```python
from adapters.detection.ids_adapter import IDSDetectionAdapter

adapter = IDSDetectionAdapter()

result = adapter.detect(
    {
        "Destination Port": 80,
        "Flow Duration": 500000,
        "Total Fwd Packets": 5,
        "Total Backward Packets": 4,
        "Flow Packets/s": 18,
    }
)
```

The adapter delegates to:

- `inference.load_artifacts()`
- `inference.predict()`

It does not duplicate IDS feature alignment, scaling, model prediction, label
decoding, or probability extraction logic.

## DetectionResult Mapping

The adapter generates platform IDs because raw flow dictionaries do not contain
`event_id`, `correlation_id`, or `trace_id`, and this component must not depend
on `SecurityEvent`.

| Field | Source |
| --- | --- |
| `predicted_label` | `inference.predict()` prediction |
| `confidence` | highest model probability from `inference.predict()` |
| `probabilities` | `prob_*` columns from `inference.predict()` |
| `status` | `BENIGN` for benign label, `DETECTED` for confident non-benign, `INCONCLUSIVE` for low-confidence non-benign |
| `risk_score` | `0` for benign, confidence-scaled for non-benign |
| `severity` | derived from `risk_score` |
| `feature_snapshot` | numeric values from the raw flow dictionary |
| `audit` | adapter-created IDS audit metadata |

## Future Detector Interface

Future detector integrations should implement `DetectionAdapter.detect()`:

```python
def detect(self, flow_data: dict[str, Any]) -> DetectionResult:
    ...
```

This keeps Suricata, Zeek, YARA, deep learning models, and the current IDS model
behind the same platform-facing contract without turning adapters into agents.
