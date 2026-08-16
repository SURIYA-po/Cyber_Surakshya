"""Ingestion layer domain exceptions."""
from __future__ import annotations


class IngestionError(Exception):
    """Base exception for all ingestion failures."""


class FeatureContractError(IngestionError):
    """Raised when the flow source cannot satisfy the model's feature contract.

    This is deliberately fatal rather than recoverable. A flow missing features
    could be zero-filled and pushed through the pipeline, and the model would
    return a confident, plausible, wrong answer — the single most damaging
    failure mode this platform has, because nothing downstream can detect it.

    Better to refuse the source than to silently fabricate detections.
    """


class UnmappedFeatureError(FeatureContractError):
    """Raised when a model feature has no source column mapping defined.

    Signals that the model was retrained with features the normalizer does not
    know how to produce. Caught at startup, not per flow.
    """
