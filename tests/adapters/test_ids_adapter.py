"""Tests for the IDS detection adapter."""

from __future__ import annotations

from typing import Any

import pytest

from adapters.detection.ids_adapter import (
    ANOMALY_ONLY_RISK,
    DEFAULT_ATTACK_BASE_RISK,
    UNKNOWN_ATTACK_BASE_RISK,
    IDSArtifacts,
    IDSDetectionAdapter,
)
from cyber_surakshya.platform.enums.detection_status import DetectionStatus
from cyber_surakshya.platform.schemas.detection_result import DetectionResult


class FakeScaler:
    def transform(self, values: Any) -> Any:
        return values


class FakeLabelEncoder:
    classes_ = ["BENIGN", "DDoS"]

    def inverse_transform(self, values: Any) -> list[str]:
        return [self.classes_[int(value)] for value in values]


class FakeIsolationForest:
    """Stand-in for the Isolation Forest half of the anomaly layer."""

    def __init__(self, score: float) -> None:
        self.score = score

    def score_samples(self, values: Any):
        import numpy as np

        return np.array([self.score] * len(values))


class FakeAutoencoder:
    """Stand-in for the autoencoder half of the anomaly layer."""

    def __init__(self, error: float) -> None:
        self.error = error

    def reconstruction_error(self, values: Any):
        import numpy as np

        return np.array([self.error] * len(values))


def make_artifacts_with_anomaly_layer(
    prediction: int,
    probabilities: list[float],
    *,
    anomaly: bool,
) -> IDSArtifacts:
    """Artifacts whose anomaly layer fires (or does not) deterministically."""
    return IDSArtifacts(
        model=FakeModel(prediction, probabilities),
        scaler=FakeScaler(),
        label_encoder=FakeLabelEncoder(),
        feature_columns=["Destination Port", "Flow Packets/s"],
        # Threshold is 0.0: a negative score is anomalous, a positive one is not.
        iforest=FakeIsolationForest(-1.0 if anomaly else 1.0),
        autoencoder=FakeAutoencoder(-1.0),
        if_threshold=0.0,
        ae_threshold=0.0,
    )


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
    # is_anomaly now reports the UNSUPERVISED layer's verdict. These artifacts
    # carry no anomaly layer, so it is False even though an attack was
    # detected. It used to be an alias for `status == DETECTED`.
    assert result.is_anomaly is False
    # Risk is class consequence x confidence, not confidence x 100.
    assert result.risk_score.value == round(DEFAULT_ATTACK_BASE_RISK["DDOS"] * 0.96, 4)
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
    # Halved base risk for a label the classifier will not stand behind.
    assert result.risk_score.value == round(
        DEFAULT_ATTACK_BASE_RISK["DDOS"] * 0.51 * 0.5, 4
    )


def test_anomaly_layer_runs_and_is_reported_separately_from_the_label():
    """The unsupervised layer must actually execute in the adapter path.

    It previously did not: the adapter unpacked the artifacts into the
    positional form of inference.predict, which hard-codes anomaly_ready=False.
    Isolation Forest and the autoencoder were loaded at startup and ignored.
    """
    adapter = IDSDetectionAdapter(
        artifacts=make_artifacts_with_anomaly_layer(
            prediction=1, probabilities=[0.04, 0.96], anomaly=True
        ),
    )

    result = adapter.detect({"Destination Port": 80, "Flow Packets/s": 20000})

    assert result.status == DetectionStatus.DETECTED
    assert result.is_anomaly is True
    assert result.metadata["anomaly_layer"] == "active"
    assert result.metadata["if_anomaly"] is True
    # Both layers agreeing raises risk above the label-only score.
    assert result.risk_score.value > DEFAULT_ATTACK_BASE_RISK["DDOS"] * 0.96


def test_benign_label_with_anomaly_becomes_inconclusive():
    """A novel attack the classifier sorts into BENIGN must not read as safe.

    This is the entire reason the second, unsupervised layer was trained. The
    path was unreachable while the anomaly layer was disconnected, which also
    made DecisionRule 'inconclusive_soc_review' rationale factually false.
    """
    adapter = IDSDetectionAdapter(
        artifacts=make_artifacts_with_anomaly_layer(
            prediction=0, probabilities=[0.98, 0.02], anomaly=True
        ),
    )

    result = adapter.detect({"Destination Port": 443, "Flow Packets/s": 12})

    assert result.predicted_label == "BENIGN"
    assert result.status == DetectionStatus.INCONCLUSIVE
    assert result.is_anomaly is True
    assert result.risk_score.value == ANOMALY_ONLY_RISK


def test_portscan_does_not_reach_auto_block_risk_at_full_confidence():
    """Reconnaissance must not score the same as a volumetric attack.

    Risk was `confidence * 100`, so a 0.99-confidence port scan scored 99 —
    over DecisionRule 1's threshold of 80, which blocks an IP with
    requires_approval=False. Scanning is constant background noise on any
    public interface; auto-blocking every scanner is self-harm.
    """

    class PortScanEncoder:
        classes_ = ["BENIGN", "PORTSCAN"]

        def inverse_transform(self, values: Any) -> list[str]:
            return [self.classes_[int(v)] for v in values]

    adapter = IDSDetectionAdapter(
        artifacts=IDSArtifacts(
            model=FakeModel(1, [0.01, 0.99]),
            scaler=FakeScaler(),
            label_encoder=PortScanEncoder(),
            feature_columns=["Destination Port", "Flow Packets/s"],
        )
    )

    result = adapter.detect({"Destination Port": 0, "Flow Packets/s": 10000})

    assert result.status == DetectionStatus.DETECTED
    assert result.predicted_label == "PORTSCAN"
    assert result.risk_score.value < 80.0
    assert result.severity.name in {"LOW", "MEDIUM"}


def test_unknown_attack_label_scores_mid_range():
    """A retrained model with new classes must not default to harmless."""

    class NovelEncoder:
        classes_ = ["BENIGN", "RANSOMWARE"]

        def inverse_transform(self, values: Any) -> list[str]:
            return [self.classes_[int(v)] for v in values]

    adapter = IDSDetectionAdapter(
        artifacts=IDSArtifacts(
            model=FakeModel(1, [0.1, 0.9]),
            scaler=FakeScaler(),
            label_encoder=NovelEncoder(),
            feature_columns=["Destination Port", "Flow Packets/s"],
        )
    )

    result = adapter.detect({"Destination Port": 445, "Flow Packets/s": 50})

    assert result.risk_score.value == round(UNKNOWN_ATTACK_BASE_RISK * 0.9, 4)


def test_adapter_refuses_a_mostly_zero_filled_flow():
    """Zero-filling missing features produces a confident, meaningless label.

    The observed failure was a whole capture scored as BENIGN at confidence
    1.0 because none of the input column names matched the model's schema.
    """
    adapter = IDSDetectionAdapter(
        artifacts=IDSArtifacts(
            model=FakeModel(0, [1.0, 0.0]),
            scaler=FakeScaler(),
            label_encoder=FakeLabelEncoder(),
            feature_columns=[f"Feature {i}" for i in range(10)],
        ),
        min_feature_coverage=0.5,
    )

    with pytest.raises(Exception, match="Refusing to predict"):
        adapter.detect({"Feature 0": 1.0, "unrelated_column": 2.0})


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
