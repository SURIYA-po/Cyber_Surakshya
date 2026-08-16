"""Module 2 — Metrics Engine.

Computes platform performance from incident history.

Two rules govern every metric here:

1. **Ground-truth metrics require analyst labels.** False positives, false
   negatives, precision, recall, and decision accuracy are computed only over
   incidents an analyst has ruled on. The platform cannot mark its own
   homework.

2. **Every metric carries its sample size, and reports nothing below a
   floor.** A 93% accuracy computed from two labels is more dangerous than no
   number at all — it will be read as fact and acted on. Below
   ``min_sample_size`` the value is None and ``sufficient_data`` is False.
"""
from __future__ import annotations

import logging
from statistics import mean

from agents.learning.outcome_collector import IncidentHistory
from cyber_surakshya.platform.schemas.learning_report import (
    AnalystVerdict,
    MetricSummary,
)

logger = logging.getLogger(__name__)

DEFAULT_MIN_SAMPLE_SIZE = 10

# Response statuses that represent an attempted action, and those that
# represent success. AWAITING_APPROVAL and BLOCKED_BY_GUARD are excluded from
# the denominator entirely: the response layer working as designed is not a
# response failure, and counting it as one would push the recommendation
# engine toward loosening the safety gates.
_ATTEMPTED_STATUSES = frozenset({
    "EXECUTED", "DRY_RUN", "NO_OP", "DOWNGRADED", "FAILED", "REVERTED",
})
_SUCCESS_STATUSES = frozenset({
    "EXECUTED", "DRY_RUN", "NO_OP", "DOWNGRADED", "REVERTED",
})
_GUARD_INTERVENTION_STATUSES = frozenset({"DOWNGRADED", "BLOCKED_BY_GUARD"})


class MetricsEngine:
    """Turns incident history into measured, evidence-qualified metrics."""

    def __init__(self, *, min_sample_size: int = DEFAULT_MIN_SAMPLE_SIZE) -> None:
        if min_sample_size < 1:
            raise ValueError("min_sample_size must be at least 1.")
        self.min_sample_size = min_sample_size

    def compute(self, incidents: list[IncidentHistory]) -> list[MetricSummary]:
        """Compute the full metric set for a body of incident history."""
        labeled = [i for i in incidents if i.is_labeled]

        metrics: list[MetricSummary] = [
            self._volume_metrics(incidents),
            self._detection_rate(incidents),
            *self._ground_truth_metrics(labeled),
            self._decision_accuracy(labeled),
            self._mttd(incidents),
            self._mttr(incidents),
            self._response_success_rate(incidents),
            self._approval_rate(incidents),
            self._guard_intervention_rate(incidents),
        ]

        logger.info(
            "learning_metrics_computed",
            extra={
                "incidents":       len(incidents),
                "labeled":         len(labeled),
                "metrics":         len(metrics),
                "min_sample_size": self.min_sample_size,
            },
        )
        return metrics

    # ── Volume ────────────────────────────────────────────────────────────────

    def _volume_metrics(self, incidents: list[IncidentHistory]) -> MetricSummary:
        complete = sum(1 for i in incidents if i.is_complete)
        return MetricSummary(
            name="pipeline_completion_rate",
            value=(complete / len(incidents)) if incidents else None,
            unit="ratio",
            sample_size=len(incidents),
            sufficient_data=bool(incidents),
            detail=f"{complete} of {len(incidents)} incident(s) traversed every stage",
        )

    def _detection_rate(self, incidents: list[IncidentHistory]) -> MetricSummary:
        threats = sum(1 for i in incidents if i.is_threat)
        return MetricSummary(
            name="threat_detection_rate",
            value=(threats / len(incidents)) if incidents else None,
            unit="ratio",
            sample_size=len(incidents),
            sufficient_data=bool(incidents),
            detail=f"{threats} of {len(incidents)} incident(s) classified as a threat",
        )

    # ── Ground truth (requires analyst labels) ────────────────────────────────

    def _ground_truth_metrics(
        self,
        labeled: list[IncidentHistory],
    ) -> list[MetricSummary]:
        """False positives, false negatives, precision, and recall.

        Confusion matrix, where "positive" means the platform called it a threat:

          TP — threat detection the analyst confirmed
          FP — threat detection the analyst rejected
          FN — benign detection the analyst rejected (a real threat was missed)
          TN — benign detection the analyst confirmed

        One verdict combination is contradictory: FALSE_POSITIVE on a benign
        detection. Nothing was flagged, so there is no positive to be false.
        Such rulings are excluded and counted separately rather than folded
        into FN — silently reinterpreting a verdict as the opposite error
        class would corrupt exactly the ground truth this module exists to
        protect.
        """
        tp = fp = fn = tn = contradictory = 0
        for incident in labeled:
            verdict = incident.feedback.verdict          # type: ignore[union-attr]
            if incident.is_threat:
                if verdict in (AnalystVerdict.CORRECT, AnalystVerdict.ESCALATE):
                    tp += 1
                else:                                    # INCORRECT / FALSE_POSITIVE
                    fp += 1
            else:
                if verdict is AnalystVerdict.CORRECT:
                    tn += 1
                elif verdict is AnalystVerdict.FALSE_POSITIVE:
                    contradictory += 1
                    logger.warning(
                        "learning_contradictory_verdict",
                        extra={
                            "detection_id":    incident.detection_id,
                            "verdict":         verdict.value,
                            "predicted_label": incident.predicted_label,
                            "reason": (
                                "FALSE_POSITIVE recorded against a benign detection; "
                                "excluded from the confusion matrix"
                            ),
                        },
                    )
                else:                                    # INCORRECT / ESCALATE
                    fn += 1

        total = tp + fp + fn + tn
        enough = total >= self.min_sample_size
        shortfall = (
            None if enough
            else (
                f"needs {self.min_sample_size} usable analyst-labelled "
                f"incident(s), has {total}"
                + (
                    f" ({contradictory} contradictory verdict(s) excluded)"
                    if contradictory else ""
                )
            )
        )

        def summary(name: str, value: float | None, detail: str) -> MetricSummary:
            return MetricSummary(
                name=name,
                value=value if enough else None,
                unit="ratio",
                sample_size=total,
                sufficient_data=enough and value is not None,
                detail=detail if enough else shortfall,
            )

        predicted_positive = tp + fp
        actual_positive    = tp + fn

        return [
            summary(
                "false_positive_rate",
                (fp / predicted_positive) if predicted_positive else None,
                f"{fp} false positive(s) across {predicted_positive} threat detection(s)",
            ),
            summary(
                "false_negative_rate",
                (fn / actual_positive) if actual_positive else None,
                f"{fn} missed threat(s) across {actual_positive} actual threat(s)",
            ),
            summary(
                "precision",
                (tp / predicted_positive) if predicted_positive else None,
                f"{tp} confirmed of {predicted_positive} threat detection(s)",
            ),
            summary(
                "recall",
                (tp / actual_positive) if actual_positive else None,
                f"{tp} caught of {actual_positive} actual threat(s)",
            ),
            summary(
                "detection_accuracy",
                ((tp + tn) / total) if total else None,
                f"{tp + tn} correct of {total} labelled incident(s)",
            ),
        ]

    def _decision_accuracy(self, labeled: list[IncidentHistory]) -> MetricSummary:
        """Fraction of decisions an analyst judged correct.

        Scoped to incidents that actually produced a decision, so an incident
        labelled before the pipeline reached DecisionAgent does not count
        against the decision layer.
        """
        decided = [i for i in labeled if i.decision]
        correct = sum(
            1 for i in decided
            if i.feedback.verdict is AnalystVerdict.CORRECT   # type: ignore[union-attr]
        )
        enough = len(decided) >= self.min_sample_size
        return MetricSummary(
            name="decision_accuracy",
            value=(correct / len(decided)) if (enough and decided) else None,
            unit="ratio",
            sample_size=len(decided),
            sufficient_data=enough and bool(decided),
            detail=(
                f"{correct} of {len(decided)} decision(s) confirmed correct"
                if enough
                else f"needs {self.min_sample_size} labelled decision(s), has {len(decided)}"
            ),
        )

    # ── Timing ────────────────────────────────────────────────────────────────

    def _mttd(self, incidents: list[IncidentHistory]) -> MetricSummary:
        samples = [t for t in (i.time_to_detect() for i in incidents) if t is not None]
        return self._duration_metric(
            "mttd_seconds",
            samples,
            "observation to detection",
            len(incidents),
        )

    def _mttr(self, incidents: list[IncidentHistory]) -> MetricSummary:
        samples = [t for t in (i.time_to_respond() for i in incidents) if t is not None]
        return self._duration_metric(
            "mttr_seconds",
            samples,
            "observation to containment",
            len(incidents),
        )

    def _duration_metric(
        self,
        name: str,
        samples: list[float],
        description: str,
        total: int,
    ) -> MetricSummary:
        """Mean duration over the incidents where it is measurable.

        Incidents lacking stage timestamps are excluded rather than defaulted
        to zero — records written before those timestamps were persisted would
        otherwise report a flawless response time built from missing data.
        """
        if not samples:
            return MetricSummary(
                name=name,
                value=None,
                unit="seconds",
                sample_size=0,
                sufficient_data=False,
                detail=(
                    f"no incident carries the timestamps needed to measure "
                    f"{description}; records predating stage-timestamp "
                    "persistence are excluded"
                ),
            )
        return MetricSummary(
            name=name,
            value=mean(samples),
            unit="seconds",
            sample_size=len(samples),
            sufficient_data=True,
            detail=(
                f"mean {description} over {len(samples)} measurable of "
                f"{total} incident(s)"
            ),
        )

    # ── Response layer ────────────────────────────────────────────────────────

    def _response_success_rate(self, incidents: list[IncidentHistory]) -> MetricSummary:
        attempted = succeeded = 0
        for incident in incidents:
            for response in incident.responses:
                status = str(response.get("status", ""))
                if status in _ATTEMPTED_STATUSES:
                    attempted += 1
                    if status in _SUCCESS_STATUSES:
                        succeeded += 1
        return MetricSummary(
            name="response_success_rate",
            value=(succeeded / attempted) if attempted else None,
            unit="ratio",
            sample_size=attempted,
            sufficient_data=bool(attempted),
            detail=(
                f"{succeeded} of {attempted} attempted action(s) succeeded; "
                "actions awaiting approval or blocked by the guard are excluded "
                "as not attempted"
            ),
        )

    def _approval_rate(self, incidents: list[IncidentHistory]) -> MetricSummary:
        ruled = granted = 0
        for incident in incidents:
            if not incident.approval:
                continue
            ruled += 1
            if incident.approval.get("approved") is True:
                granted += 1
        return MetricSummary(
            name="approval_rate",
            value=(granted / ruled) if ruled else None,
            unit="ratio",
            sample_size=ruled,
            sufficient_data=bool(ruled),
            detail=f"{granted} of {ruled} analyst ruling(s) granted approval",
        )

    def _guard_intervention_rate(
        self,
        incidents: list[IncidentHistory],
    ) -> MetricSummary:
        """How often the safety layer overrode what the decision layer chose.

        A high rate is not necessarily bad — it may mean the guard is doing
        its job against an untrusted engine — but it is always worth knowing.
        """
        total = intervened = 0
        for incident in incidents:
            for response in incident.responses:
                total += 1
                if str(response.get("status", "")) in _GUARD_INTERVENTION_STATUSES:
                    intervened += 1
        return MetricSummary(
            name="guard_intervention_rate",
            value=(intervened / total) if total else None,
            unit="ratio",
            sample_size=total,
            sufficient_data=bool(total),
            detail=(
                f"the guard downgraded or blocked {intervened} of {total} response(s)"
            ),
        )
