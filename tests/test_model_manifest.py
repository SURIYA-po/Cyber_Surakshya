"""The manifest is what keeps a blind model out of production.

Three of the four models this project trains score >0.99 weighted F1 while
catching 8-10% of WEBATTACK. Before the manifest, which one got served was
decided by `resolve_model_path`'s hardcoded list order and whichever files
happened to be on disk — so writing a `model.pkl` from the wrong estimator
silently blinded the detector to an entire attack family with every headline
metric still reading 99%.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import inference

ARTIFACT_DIR = Path(inference.ARTIFACT_DIR)


# ── The shipped manifest ──────────────────────────────────────────────────────


def _manifest() -> dict:
    manifest = inference.load_manifest(str(ARTIFACT_DIR))
    if manifest is None:
        pytest.skip(
            "artifacts/manifest.json missing; generate it with "
            "python scripts/build_manifest.py"
        )
    return manifest


def test_manifest_names_a_model_that_exists():
    manifest = _manifest()
    served = manifest["served_model"]
    assert (ARTIFACT_DIR / served).exists(), (
        f"manifest names {served!r} but it is not in {ARTIFACT_DIR}"
    )


def test_resolve_model_path_honours_the_manifest():
    manifest = _manifest()
    resolved = Path(inference.resolve_model_path(str(ARTIFACT_DIR)))
    assert resolved.name == manifest["served_model"]


def test_served_model_is_not_blind_to_any_attack_class():
    """The regression guard. A served model must detect every class it claims."""
    manifest = _manifest()
    served = manifest["served_model_name"]
    metrics = manifest["metrics"][served]

    worst_class = metrics["worst_class"]
    worst_recall = metrics["min_class_recall"]

    assert worst_recall >= 0.50, (
        f"The served model ({served}) catches only {worst_recall:.0%} of "
        f"{worst_class}. A model that misses most of an attack family must not "
        f"be in production."
    )


def test_manifest_records_every_trained_model_not_just_the_served_one():
    """The rejected models' weaknesses must stay visible, not be dropped."""
    manifest = _manifest()
    metrics = manifest["metrics"]
    assert len(metrics) >= 2, "Only one model recorded; comparison is impossible."
    for name, m in metrics.items():
        assert "min_class_recall" in m, f"{name} has no per-class recall floor"
        assert "per_class_recall" in m, f"{name} has no per-class breakdown"


def test_manifest_identifies_the_artifacts_it_describes():
    manifest = _manifest()
    assert manifest["feature_count"] == 42
    classes = manifest["classes"]
    assert "BENIGN" in classes
    # Seven, not eight: there is no INFILTRATION class in the cleaned dataset.
    assert "INFILTRATION" not in classes
    assert len(classes) == 7

    repro = manifest["reproducibility"]
    for key in ("dataset", "random_state", "python", "scikit_learn", "numpy"):
        assert key in repro, f"reproducibility is missing {key!r}"


# ── Resolution precedence ─────────────────────────────────────────────────────


def test_explicit_request_beats_the_manifest(tmp_path: Path):
    (tmp_path / "manifest.json").write_text(
        json.dumps({"served_model": "model_DNN.pkl"}), encoding="utf-8"
    )
    (tmp_path / "model_DNN.pkl").write_bytes(b"dnn")
    (tmp_path / "custom.pkl").write_bytes(b"custom")

    resolved = inference.resolve_model_path(str(tmp_path), "custom.pkl")
    assert Path(resolved).name == "custom.pkl"


def test_manifest_beats_the_legacy_name_order(tmp_path: Path):
    """model.pkl is first in the fallback list; the manifest must still win.

    This is the case that matters: dropping a `model.pkl` built from a weak
    estimator used to override everything.
    """
    (tmp_path / "manifest.json").write_text(
        json.dumps({"served_model": "model_DNN.pkl"}), encoding="utf-8"
    )
    (tmp_path / "model.pkl").write_bytes(b"some other model")
    (tmp_path / "model_DNN.pkl").write_bytes(b"dnn")

    resolved = inference.resolve_model_path(str(tmp_path))
    assert Path(resolved).name == "model_DNN.pkl"


def test_falls_back_to_name_order_when_the_manifest_points_at_nothing(tmp_path: Path):
    """A stale manifest must not make the platform unbootable."""
    (tmp_path / "manifest.json").write_text(
        json.dumps({"served_model": "model_Deleted.pkl"}), encoding="utf-8"
    )
    (tmp_path / "model.pkl").write_bytes(b"fallback")

    resolved = inference.resolve_model_path(str(tmp_path))
    assert Path(resolved).name == "model.pkl"


def test_corrupt_manifest_is_ignored_rather_than_fatal(tmp_path: Path):
    (tmp_path / "manifest.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "model.pkl").write_bytes(b"fallback")

    assert inference.load_manifest(str(tmp_path)) is None
    assert Path(inference.resolve_model_path(str(tmp_path))).name == "model.pkl"


def test_missing_manifest_is_not_an_error(tmp_path: Path):
    (tmp_path / "model_RandomForest.pkl").write_bytes(b"rf")
    assert inference.load_manifest(str(tmp_path)) is None
    assert Path(
        inference.resolve_model_path(str(tmp_path))
    ).name == "model_RandomForest.pkl"
