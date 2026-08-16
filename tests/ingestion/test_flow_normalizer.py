"""Tests for the cicflowmeter → model feature contract.

This is the Phase 0 gate for the real-time ingestion layer. Two silent
mismatches sit between the vendored Python cicflowmeter and the CICIDS2017
model — snake_case naming and a seconds/microseconds unit difference — and
neither raises. Both produce confident, plausible, wrong classifications.

The fixture is real cicflowmeter output (9 flows, 82 columns) so the tests
exercise the actual schema rather than a hand-written approximation.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from ingestion.exceptions import FeatureContractError, UnmappedFeatureError
from ingestion.flows.normalizer import (
    DEFAULT_FEATURE_COLUMNS_PATH,
    FEATURE_SOURCE_MAP,
    MICROSECOND_FEATURES,
    RATE_FEATURES,
    SECONDS_TO_MICROSECONDS,
    FlowNormalizer,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cicflowmeter_sample.csv"


@pytest.fixture
def frame() -> pd.DataFrame:
    return pd.read_csv(FIXTURE)


@pytest.fixture
def normalizer() -> FlowNormalizer:
    return FlowNormalizer()


@pytest.fixture
def flow(frame) -> dict:
    """A flow with non-zero duration, so unit conversion is observable."""
    rows = frame[frame.flow_duration > 0]
    assert not rows.empty, "fixture must contain a non-zero-duration flow"
    return rows.iloc[0].to_dict()


# ── The artifact ──────────────────────────────────────────────────────────────


def test_feature_columns_artifact_is_uncorrupted():
    """`pyDestination Port` is the misspelled column name in the source dataset.

    The training CSV's own header carries the typo and preprocess.py copies
    column names through verbatim, so it reached the artifact. The values are
    genuine destination ports and the scaler is positional, which makes the
    rename harmless to the model but essential for name-based ingestion.
    """
    columns = json.loads(DEFAULT_FEATURE_COLUMNS_PATH.read_text(encoding="utf-8"))

    assert len(columns) == 42
    assert "Destination Port" in columns
    assert "pyDestination Port" not in columns
    for name in columns:
        assert name == name.strip(), f"{name!r} has surrounding whitespace"


# ── Contract coverage ─────────────────────────────────────────────────────────


def test_every_model_feature_has_a_source_mapping(normalizer):
    unmapped = [f for f in normalizer.feature_order if f not in FEATURE_SOURCE_MAP]

    assert unmapped == []
    assert len(normalizer.feature_order) == 42


def test_real_cicflowmeter_output_satisfies_the_contract(normalizer, frame):
    """The regression this module exists to prevent: 0 of 42 used to map."""
    normalizer.validate_source_columns(frame.columns)

    flows = normalizer.normalize_frame(frame)

    assert len(flows) == len(frame)
    assert normalizer.stats.rejected == 0
    for normalized in flows:
        assert len(normalized.features) == 42
        assert set(normalized.features) == set(normalizer.feature_order)


def test_missing_source_column_is_refused_not_zero_filled(normalizer, frame):
    degraded = frame.drop(columns=["flow_duration", "fwd_iat_max"])

    with pytest.raises(FeatureContractError) as exc:
        normalizer.validate_source_columns(degraded.columns)

    assert "flow_duration" in str(exc.value)
    assert "fwd_iat_max" in str(exc.value)


def test_model_with_unknown_features_fails_at_construction():
    """Retraining with new features must fail loudly, not mismatch silently."""
    with pytest.raises(UnmappedFeatureError):
        FlowNormalizer(feature_order=["Flow Duration", "Some New Feature"])


# ── Units: the dangerous half ─────────────────────────────────────────────────


def test_time_features_are_converted_seconds_to_microseconds(normalizer, flow):
    result = normalizer.normalize(flow)

    for name in MICROSECOND_FEATURES:
        source = FEATURE_SOURCE_MAP[name]
        expected = float(flow[source]) * SECONDS_TO_MICROSECONDS
        assert result.features[name] == pytest.approx(expected), name


def test_flow_duration_lands_in_the_cicids2017_scale(normalizer, flow):
    """Sub-millisecond in seconds becomes ~10^3 microseconds."""
    raw = float(flow["flow_duration"])
    result = normalizer.normalize(flow)

    assert result.features["Flow Duration"] == pytest.approx(raw * 1_000_000.0)
    assert result.features["Flow Duration"] > raw


def test_rate_features_are_never_scaled(normalizer, flow):
    """The inverse mistake — scaling per-second rates — is just as destructive."""
    result = normalizer.normalize(flow)

    for name in RATE_FEATURES:
        source = FEATURE_SOURCE_MAP[name]
        assert result.features[name] == pytest.approx(float(flow[source])), name


def test_time_and_rate_feature_sets_are_disjoint():
    """A feature cannot be both, and a name heuristic would confuse them."""
    assert MICROSECOND_FEATURES & RATE_FEATURES == frozenset()


def test_every_converted_feature_is_a_real_model_feature(normalizer):
    known = set(normalizer.feature_order)

    assert MICROSECOND_FEATURES <= known
    assert RATE_FEATURES <= known


def test_thirteen_features_require_conversion(normalizer):
    """Pins the count so a mapping edit cannot silently drop a conversion."""
    converted = MICROSECOND_FEATURES & set(normalizer.feature_order)

    assert len(converted) == 13


# ── Degraded input ────────────────────────────────────────────────────────────


def test_strict_mode_refuses_a_missing_value(normalizer, flow):
    flow["flow_duration"] = None

    with pytest.raises(FeatureContractError, match="flow_duration"):
        normalizer.normalize(flow)


def test_strict_mode_refuses_a_non_numeric_value(normalizer, flow):
    flow["tot_fwd_pkts"] = "not-a-number"

    with pytest.raises(FeatureContractError, match="tot_fwd_pkts"):
        normalizer.normalize(flow)


def test_lenient_mode_fills_and_counts(flow):
    lenient = FlowNormalizer(strict=False)
    flow["flow_duration"] = None

    result = lenient.normalize(flow)

    assert result.features["Flow Duration"] == 0.0
    assert lenient.stats.missing_values_filled == 1
    assert any("missing" in w for w in result.warnings), "the fill must be visible"


def test_infinite_rate_is_clamped_not_zeroed(flow):
    """A single-packet flow has zero duration, so bytes/s is undefined.

    Zeroing would erase the extreme-rate signal that distinguishes a scan from
    an idle connection.
    """
    normalizer = FlowNormalizer(max_finite_value=1e9)
    flow["flow_byts_s"] = float("inf")

    result = normalizer.normalize(flow)

    assert result.features["Flow Bytes/s"] == 1e9
    assert normalizer.stats.non_finite_clamped == 1
    assert any("infinite" in w for w in result.warnings)


def test_nan_becomes_zero_and_is_counted(flow):
    normalizer = FlowNormalizer()
    flow["pkt_len_var"] = float("nan")

    result = normalizer.normalize(flow)

    assert result.features["Packet Length Variance"] == 0.0
    assert normalizer.stats.non_finite_clamped == 1


def test_batch_skips_bad_flows_without_aborting(normalizer, frame):
    records = frame.to_dict(orient="records")
    records[0]["flow_duration"] = "corrupt"

    flows = normalizer.normalize_many(records)

    assert len(flows) == len(records) - 1
    assert normalizer.stats.rejected == 1


# ── Identity and metadata ─────────────────────────────────────────────────────


def test_flow_id_is_deterministic_for_replay_dedup(normalizer, flow):
    """Replaying a pcap must not fabricate a volumetric attack."""
    first = normalizer.normalize(dict(flow))
    second = normalizer.normalize(dict(flow))

    assert first.flow_id == second.flow_id
    assert len(first.flow_id) == 64


def test_flow_id_differs_across_flows(normalizer, flow):
    other = dict(flow)
    other["src_port"] = int(flow["src_port"]) + 1

    assert normalizer.normalize(flow).flow_id != normalizer.normalize(other).flow_id


def test_network_metadata_is_carried_through(normalizer, flow):
    result = normalizer.normalize(flow)

    assert result.source_ip == str(flow["src_ip"])
    assert result.destination_ip == str(flow["dst_ip"])
    assert result.destination_port == int(flow["dst_port"])
    assert result.protocol == int(flow["protocol"])
    assert result.timestamp


def test_feature_vector_follows_model_column_order(normalizer, flow):
    result = normalizer.normalize(flow)

    vector = result.feature_vector(normalizer.feature_order)

    assert len(vector) == 42
    assert vector[0] == result.features[normalizer.feature_order[0]]
    assert all(isinstance(v, float) for v in vector)


# ── End to end ────────────────────────────────────────────────────────────────


def test_normalized_flows_are_accepted_by_the_trained_model(normalizer, frame):
    """The full Phase 0 objective: real capture output reaches the model."""
    import numpy as np

    import inference

    artifacts = inference.IDSArtifacts(
        model_path=inference.resolve_model_path("artifacts"),
        scaler_path="artifacts/scaler.pkl",
        le_path="artifacts/label_encoder.pkl",
        feat_path="artifacts/feature_columns.json",
    )
    flows = normalizer.normalize_frame(frame)

    matrix = np.array(
        [f.feature_vector(artifacts.feature_cols) for f in flows], dtype=float
    )
    predictions = artifacts.model.predict(artifacts.scaler.transform(matrix))

    assert matrix.shape == (len(flows), 42)
    assert np.isfinite(matrix).all(), "no NaN or inf may reach the scaler"
    assert len(predictions) == len(flows)
