"""Real-time ingestion layer.

Produces SecurityEvents from live network capture. Peer of ``adapters/``, not
part of it: an adapter bridges a detector's output into platform schemas,
while this produces the input a detector consumes.

Phase 0 (this milestone) delivers the feature contract only — see
``docs/realtime_ingestion.md``.
"""
from __future__ import annotations

from ingestion.exceptions import (
    FeatureContractError,
    IngestionError,
    UnmappedFeatureError,
)
from ingestion.flows.normalizer import (
    FEATURE_SOURCE_MAP,
    MICROSECOND_FEATURES,
    RATE_FEATURES,
    SECONDS_TO_MICROSECONDS,
    FlowNormalizer,
    NormalizedFlow,
    NormalizerStats,
)

__all__ = [
    "FEATURE_SOURCE_MAP",
    "MICROSECOND_FEATURES",
    "RATE_FEATURES",
    "SECONDS_TO_MICROSECONDS",
    "FeatureContractError",
    "FlowNormalizer",
    "IngestionError",
    "NormalizedFlow",
    "NormalizerStats",
    "UnmappedFeatureError",
]
