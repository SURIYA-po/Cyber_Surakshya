"""Flow normalization — the feature contract between cicflowmeter and the model.

This module is the reason Phase 0 of the ingestion plan blocks everything else.
Two independent mismatches sit between the vendored Python cicflowmeter and the
CICIDS2017-trained model, and both are silent:

1. NAMING. cicflowmeter emits snake_case (``flow_duration``, ``tot_fwd_pkts``).
   The model expects CICIDS2017 Title Case (``Flow Duration``, ``Total Fwd
   Packets``). ``inference.CICFLOW_ALIASES`` covers only the *Java* CICFlowMeter
   spelling, so zero of the 42 model features map without this module.

2. UNITS — the dangerous one. CICIDS2017 expresses durations and inter-arrival
   times in MICROSECONDS; the Python cicflowmeter emits SECONDS. Measured on
   ``out.csv``: ``flow_duration`` has median 0.00097 and max 10.48, while the
   platform's own CICIDS2017-shaped attack profiles use values like
   3_600_000_000. A rename-only mapping feeds the model values 10^6 too small.
   It would not raise. It would return confident, plausible, systematically
   wrong labels, and LearningAgent would report high accuracy on them.

The two feature groups are therefore enumerated explicitly rather than inferred
from name patterns: scaling a rate column by mistake is the same bug with the
sign flipped.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ingestion.exceptions import FeatureContractError, UnmappedFeatureError

logger = logging.getLogger(__name__)

DEFAULT_FEATURE_COLUMNS_PATH = (
    Path(__file__).resolve().parents[2] / "artifacts" / "feature_columns.json"
)

# Seconds → microseconds. CICIDS2017's time base.
SECONDS_TO_MICROSECONDS = 1_000_000.0

# Non-finite rates (a single-packet flow has zero duration, so bytes/s is
# undefined) are clamped rather than zeroed. Zeroing would erase the "extreme
# rate" signal that distinguishes a port scan from an idle connection; the
# training data had inf replaced by a median, so either choice is out of
# distribution and this one at least preserves the direction.
MAX_FINITE_VALUE = 1e9


# ── Model feature → cicflowmeter source column ───────────────────────────────
# Every entry verified against the 82 columns in out.csv.

FEATURE_SOURCE_MAP: dict[str, str] = {
    # Identity / volume
    "Destination Port":            "dst_port",
    "Total Fwd Packets":           "tot_fwd_pkts",
    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    "Subflow Fwd Bytes":           "subflow_fwd_byts",
    # Packet lengths
    "Fwd Packet Length Max":       "fwd_pkt_len_max",
    "Fwd Packet Length Mean":      "fwd_pkt_len_mean",
    "Fwd Packet Length Std":       "fwd_pkt_len_std",
    "Bwd Packet Length Max":       "bwd_pkt_len_max",
    "Bwd Packet Length Min":       "bwd_pkt_len_min",
    "Bwd Packet Length Mean":      "bwd_pkt_len_mean",
    "Bwd Packet Length Std":       "bwd_pkt_len_std",
    "Min Packet Length":           "pkt_len_min",
    "Max Packet Length":           "pkt_len_max",
    "Packet Length Mean":          "pkt_len_mean",
    "Packet Length Std":           "pkt_len_std",
    "Packet Length Variance":      "pkt_len_var",
    "Average Packet Size":         "pkt_size_avg",
    # Headers / windows
    "Fwd Header Length":           "fwd_header_len",
    "Bwd Header Length":           "bwd_header_len",
    "Init_Win_bytes_forward":      "init_fwd_win_byts",
    "Init_Win_bytes_backward":     "init_bwd_win_byts",
    "min_seg_size_forward":        "fwd_seg_size_min",
    # Flags
    "FIN Flag Count":              "fin_flag_cnt",
    "PSH Flag Count":              "psh_flag_cnt",
    "ACK Flag Count":              "ack_flag_cnt",
    # Rates — per-second in BOTH schemes. Never scaled.
    "Flow Bytes/s":                "flow_byts_s",
    "Flow Packets/s":              "flow_pkts_s",
    "Fwd Packets/s":               "fwd_pkts_s",
    "Bwd Packets/s":               "bwd_pkts_s",
    # Time domain — seconds in cicflowmeter, microseconds in CICIDS2017.
    "Flow Duration":               "flow_duration",
    "Flow IAT Mean":               "flow_iat_mean",
    "Flow IAT Std":                "flow_iat_std",
    "Flow IAT Max":                "flow_iat_max",
    "Fwd IAT Total":               "fwd_iat_tot",
    "Fwd IAT Mean":                "fwd_iat_mean",
    "Fwd IAT Std":                 "fwd_iat_std",
    "Fwd IAT Max":                 "fwd_iat_max",
    "Bwd IAT Total":               "bwd_iat_tot",
    "Bwd IAT Max":                 "bwd_iat_max",
    "Idle Mean":                   "idle_mean",
    "Idle Max":                    "idle_max",
    "Idle Min":                    "idle_min",
}

# Features requiring seconds → microseconds conversion. Enumerated, not
# pattern-matched: "Flow Bytes/s" contains no time word and "Idle Mean" does
# not contain "IAT", so any heuristic would get at least one of them wrong.
MICROSECOND_FEATURES: frozenset[str] = frozenset({
    "Flow Duration",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Bwd IAT Total", "Bwd IAT Max",
    "Idle Mean", "Idle Max", "Idle Min",
})

# Per-second rates. Listed so a test can assert they are never scaled — the
# inverse mistake is just as destructive and much harder to spot.
RATE_FEATURES: frozenset[str] = frozenset({
    "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
})

# Network metadata carried alongside the features so the bridge can build a
# SecurityEvent without re-reading the source.
METADATA_COLUMNS: dict[str, str] = {
    "source_ip":        "src_ip",
    "destination_ip":   "dst_ip",
    "source_port":      "src_port",
    "destination_port": "dst_port",
    "protocol":         "protocol",
    "timestamp":        "timestamp",
}


@dataclass(frozen=True)
class NormalizedFlow:
    """One cicflowmeter flow, converted to the model's feature contract."""

    features:         dict[str, float]
    source_ip:        str | None = None
    destination_ip:   str | None = None
    source_port:      int | None = None
    destination_port: int | None = None
    protocol:         int | None = None
    timestamp:        str | None = None
    flow_id:          str = ""
    warnings:         tuple[str, ...] = field(default_factory=tuple)

    def feature_vector(self, order: Iterable[str]) -> list[float]:
        """Return features in the model's column order."""
        return [self.features[name] for name in order]


@dataclass
class NormalizerStats:
    """Counters exposed so degraded input is visible, never silent."""

    flows_normalized:      int = 0
    non_finite_clamped:    int = 0
    missing_values_filled: int = 0
    rejected:              int = 0


class FlowNormalizer:
    """Converts cicflowmeter flow records into model-ready feature vectors.

    The model's feature list is loaded from ``artifacts/feature_columns.json``
    rather than hardcoded, so retraining with a different feature set fails
    loudly at construction instead of silently mismatching at inference.
    """

    def __init__(
        self,
        *,
        feature_columns_path: str | Path | None = None,
        feature_order: list[str] | None = None,
        strict: bool = True,
        max_finite_value: float = MAX_FINITE_VALUE,
    ) -> None:
        """
        Args:
            feature_order: model feature names in order. Loaded from the
                artifact when omitted.
            strict: raise when a source flow lacks a required column. Defaults
                True — zero-filling a missing feature produces a confident
                wrong prediction that nothing downstream can detect.
            max_finite_value: clamp for non-finite rates.
        """
        self.feature_order = feature_order or self._load_feature_order(
            feature_columns_path or DEFAULT_FEATURE_COLUMNS_PATH
        )
        self.strict           = strict
        self.max_finite_value = max_finite_value
        self.stats            = NormalizerStats()

        unmapped = [f for f in self.feature_order if f not in FEATURE_SOURCE_MAP]
        if unmapped:
            raise UnmappedFeatureError(
                f"{len(unmapped)} model feature(s) have no cicflowmeter source "
                f"mapping: {unmapped}. The model was retrained with features "
                "the ingestion layer cannot produce; extend FEATURE_SOURCE_MAP."
            )

        self.required_columns: frozenset[str] = frozenset(
            FEATURE_SOURCE_MAP[f] for f in self.feature_order
        )
        logger.info(
            "flow_normalizer_ready",
            extra={
                "model_features":     len(self.feature_order),
                "required_columns":   len(self.required_columns),
                "time_converted":     len(MICROSECOND_FEATURES & set(self.feature_order)),
                "strict":             strict,
            },
        )

    # ── Validation ────────────────────────────────────────────────────────────

    def validate_source_columns(self, columns: Iterable[str]) -> None:
        """Check a source schema once, at startup, instead of per flow.

        Raises:
            FeatureContractError: the source cannot satisfy the model.
        """
        available = {str(c).strip() for c in columns}
        missing   = sorted(self.required_columns - available)
        if missing:
            raise FeatureContractError(
                f"Flow source is missing {len(missing)} column(s) required by "
                f"the model: {missing}. Refusing the source rather than "
                "zero-filling — a fabricated feature yields a confident wrong "
                "detection that nothing downstream can catch."
            )
        logger.info(
            "flow_source_validated",
            extra={"available": len(available), "required": len(self.required_columns)},
        )

    # ── Normalization ─────────────────────────────────────────────────────────

    def normalize(self, flow: dict[str, Any]) -> NormalizedFlow:
        """Convert one cicflowmeter flow dict into model-ready features.

        Raises:
            FeatureContractError: in strict mode, when a required column is
                absent or non-numeric.
        """
        warnings: list[str] = []
        features: dict[str, float] = {}

        for name in self.feature_order:
            source = FEATURE_SOURCE_MAP[name]
            raw    = flow.get(source)

            value = self._coerce(name, source, raw, warnings)
            if name in MICROSECOND_FEATURES:
                value *= SECONDS_TO_MICROSECONDS
            features[name] = self._finite(name, value, warnings)

        normalized = NormalizedFlow(
            features=features,
            source_ip=self._as_str(flow.get("src_ip")),
            destination_ip=self._as_str(flow.get("dst_ip")),
            source_port=self._as_int(flow.get("src_port")),
            destination_port=self._as_int(flow.get("dst_port")),
            protocol=self._as_int(flow.get("protocol")),
            timestamp=self._as_str(flow.get("timestamp")),
            flow_id=self._flow_id(flow),
            warnings=tuple(warnings),
        )
        self.stats.flows_normalized += 1
        return normalized

    def normalize_many(
        self,
        flows: Iterable[dict[str, Any]],
    ) -> list[NormalizedFlow]:
        """Normalize a batch, skipping flows that violate the contract.

        Skips are counted in ``stats.rejected`` and logged. Batch processing
        must not abort on one malformed record, but the loss stays visible.
        """
        results: list[NormalizedFlow] = []
        for flow in flows:
            try:
                results.append(self.normalize(flow))
            except FeatureContractError as exc:
                self.stats.rejected += 1
                logger.warning(
                    "flow_rejected",
                    extra={"error": str(exc)[:300]},
                )
        return results

    def normalize_frame(self, frame) -> list[NormalizedFlow]:
        """Normalize a pandas DataFrame of cicflowmeter output."""
        self.validate_source_columns(frame.columns)
        return self.normalize_many(frame.to_dict(orient="records"))

    # ── Private ───────────────────────────────────────────────────────────────

    def _coerce(
        self,
        name: str,
        source: str,
        raw: Any,
        warnings: list[str],
    ) -> float:
        if raw is None or (isinstance(raw, str) and not raw.strip()):
            if self.strict:
                raise FeatureContractError(
                    f"Required column {source!r} (model feature {name!r}) is "
                    "absent or empty in the source flow."
                )
            self.stats.missing_values_filled += 1
            warnings.append(f"{name}: missing, filled 0.0")
            return 0.0
        try:
            return float(raw)
        except (TypeError, ValueError):
            if self.strict:
                raise FeatureContractError(
                    f"Column {source!r} (model feature {name!r}) is not "
                    f"numeric: {raw!r}."
                )
            self.stats.missing_values_filled += 1
            warnings.append(f"{name}: non-numeric {raw!r}, filled 0.0")
            return 0.0

    def _finite(self, name: str, value: float, warnings: list[str]) -> float:
        if math.isnan(value):
            self.stats.non_finite_clamped += 1
            warnings.append(f"{name}: NaN, set 0.0")
            return 0.0
        if math.isinf(value):
            self.stats.non_finite_clamped += 1
            clamped = self.max_finite_value if value > 0 else -self.max_finite_value
            warnings.append(f"{name}: infinite, clamped to {clamped:g}")
            return clamped
        if abs(value) > self.max_finite_value:
            self.stats.non_finite_clamped += 1
            clamped = math.copysign(self.max_finite_value, value)
            warnings.append(f"{name}: {value:g} exceeds bound, clamped")
            return clamped
        return value

    @staticmethod
    def _flow_id(flow: dict[str, Any]) -> str:
        """Deterministic identity for dedup across replays.

        Derived from the five-tuple plus timestamp, so re-processing the same
        pcap yields the same IDs. Without this, replaying a capture would
        fabricate a volumetric attack out of duplicate flows — the platform
        deliberately treats repeated identical flows as signal.
        """
        parts = [
            str(flow.get("src_ip", "")),
            str(flow.get("dst_ip", "")),
            str(flow.get("src_port", "")),
            str(flow.get("dst_port", "")),
            str(flow.get("protocol", "")),
            str(flow.get("timestamp", "")),
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    @staticmethod
    def _as_str(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _as_int(value: Any) -> int | None:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _load_feature_order(path: str | Path) -> list[str]:
        with open(path, encoding="utf-8") as handle:
            columns = json.load(handle)
        if not isinstance(columns, list) or not columns:
            raise FeatureContractError(
                f"{path} does not contain a non-empty list of feature names."
            )
        cleaned = [str(c).strip() for c in columns]
        if cleaned != list(columns):
            logger.warning(
                "feature_columns_whitespace_stripped",
                extra={"path": str(path)},
            )
        return cleaned
