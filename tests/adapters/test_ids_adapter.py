"""Tests for the IDS detection adapter."""

from __future__ import annotations

from typing import Any

import pytest

from adapters.detection.ids_adapter import IDSArtifacts, IDSDetectionAdapter
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.schemas.detection_result import DetectionResult


class FakeScaler:
    def transform(self, values: Any) -> Any:
        return values


class FakeLabelEncoder:
    classes_ = ["BENIGN", "DDoS"]

    def inverse_transform(self, values: Any) -> list[str]:
        return [self.classes_[int(value)] for value in values]


class FakeProbabilityColumn:
    def __init__(self, values: list[float]) -> None:
        self.values = values

    def round(self, digits: int) -> list[float]:
        return [round(value, digits) for value in self.values]


class FakeProbabilityMatrix:
    def __init__(self, rows: list[list[float]]) -> None:
        self.rows = rows

    def max(self, axis: int) -> FakeProbabilityColumn:
        if axis != 1:
            raise ValueError("FakeProbabilityMatrix only supports axis=1.")
        return FakeProbabilityColumn([max(row) for row in self.rows])

    def __getitem__(self, key: tuple[slice, int]) -> FakeProbabilityColumn:
        row_slice, column_index = key
        return FakeProbabilityColumn(
            [row[column_index] for row in self.rows[row_slice]]
        )


class FakeModel:
    def __init__(self, prediction: int, probabilities: list[float]) -> None:
        self.prediction = prediction
        self.probabilities = probabilities

    def predict(self, values: Any) -> list[int]:
        return [self.prediction]

    def predict_proba(self, values: Any) -> FakeProbabilityMatrix:
        return FakeProbabilityMatrix([self.probabilities])


def make_artifacts(prediction: int, probabilities: list[float]) -> IDSArtifacts:
    return IDSArtifacts(
        model=FakeModel(prediction, probabilities),
        scaler=FakeScaler(),
        label_encoder=FakeLabelEncoder(),
        feature_columns=["Destination Port", "Flow Packets/s"],
    )


def test_ids_adapter_returns_detection_result_for_attack_flow():
    adapter = IDSDetectionAdapter(
        artifacts=make_artifacts(prediction=1, probabilities=[0.04, 0.96]),
        model_version="test",
    )

    result = adapter.detect(
        {
            "Destination Port": 80,
            "Flow Packets/s": 20000,
            "non_numeric_note": "ignored in feature snapshot",
        }
    )

    assert isinstance(result, DetectionResult)
    assert result.status == DetectionStatus.DETECTED
    assert result.predicted_label == "DDoS"
    assert result.confidence == 0.96
    assert result.probabilities == {"BENIGN": 0.04, "DDoS": 0.96}
    assert result.is_anomaly is True
    assert result.risk_score.value == 96.0
    assert result.feature_snapshot == {
        "Destination Port": 80.0,
        "Flow Packets/s": 20000.0,
    }
    assert result.audit.source_system == "ids"


def test_ids_adapter_returns_benign_detection_result():
    adapter = IDSDetectionAdapter(
        artifacts=make_artifacts(prediction=0, probabilities=[0.9, 0.1])
    )

    result = adapter.detect({"Destination Port": 443, "Flow Packets/s": 12})

    assert result.status == DetectionStatus.BENIGN
    assert result.predicted_label == "BENIGN"
    assert result.is_anomaly is False
    assert result.risk_score.value == 0.0
    assert result.severity.name == "INFO"


def test_ids_adapter_marks_low_confidence_attack_as_inconclusive():
    adapter = IDSDetectionAdapter(
        artifacts=make_artifacts(prediction=1, probabilities=[0.51, 0.49]),
        min_detection_confidence=0.6,
    )

    result = adapter.detect({"Destination Port": 22, "Flow Packets/s": 30})

    assert result.status == DetectionStatus.INCONCLUSIVE
    assert result.predicted_label == "DDoS"
    assert result.is_anomaly is False
    assert result.risk_score.value == 25.5


def test_ids_adapter_rejects_empty_flow_data():
    adapter = IDSDetectionAdapter(
        artifacts=make_artifacts(prediction=0, probabilities=[1.0, 0.0])
    )

    with pytest.raises(ValueError, match="must not be empty"):
        adapter.detect({})


def test_ids_adapter_rejects_blank_flow_keys():
    adapter = IDSDetectionAdapter(
        artifacts=make_artifacts(prediction=0, probabilities=[1.0, 0.0])
    )

    with pytest.raises(ValueError, match="non-empty"):
        adapter.detect({" ": 1})


def test_ids_adapter_can_load_artifacts_with_existing_loader():
    calls: list[tuple[Any, ...]] = []

    def fake_loader(*args: Any) -> tuple[Any, Any, Any, list[str]]:
        calls.append(args)
        artifacts = make_artifacts(prediction=0, probabilities=[1.0, 0.0])
        return (
            artifacts.model,
            artifacts.scaler,
            artifacts.label_encoder,
            list(artifacts.feature_columns),
        )

    adapter = IDSDetectionAdapter(
        artifact_dir="custom-artifacts",
        artifact_loader=fake_loader,
    )

    result = adapter.detect({"Destination Port": 53, "Flow Packets/s": 5})

    assert result.status == DetectionStatus.BENIGN
    assert len(calls) == 1
    assert calls[0][0].endswith("model.pkl")
    assert calls[0][1].endswith("scaler.pkl")
    assert calls[0][2].endswith("label_encoder.pkl")
    assert calls[0][3].endswith("feature_columns.json")
