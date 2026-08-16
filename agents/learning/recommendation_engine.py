"""Module 4 — Recommendation Engine.

Turns metrics and patterns into ranked, human-actionable proposals.

IT RECOMMENDS; IT NEVER EXECUTES. Nothing in this module retrains a model,
edits response_policy.yaml, changes a threshold, or touches an executor. Every
output is a sentence describing what a human should consider doing, with the
evidence that prompted it.

This mirrors the DecisionAgent/ResponseAgent split for the same reason: a
component that both draws conclusions and acts on them has no review point.
The stakes are higher here, because the actions recommended — retraining a
model, loosening a detection threshold — are exactly the ones that would
degrade the platform invisibly if applied from a bad inference.

Second rule: **a recommendation may not rest on a metric with
``sufficient_data=False``.** Any rule whose trigger lacks evidence is
suppressed, and COLLECT_MORE_FEEDBACK is emitted instead. Acting on an
accuracy figure computed from two labels is worse than not acting.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from cyber_surakshya.platform.schemas.learning_report import (
    MetricSummary,
    Pattern,
    PatternType,
    Recommendation,
    RecommendationPriority,
    RecommendationType,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RecommendationThresholds:
    """Trigger points for each recommendation. Data, not code."""

    high_false_positive_rate:  float = 0.20
    high_false_negative_rate:  float = 0.10
    low_detection_accuracy:    float = 0.85
    low_decision_accuracy:     float = 0.80
    low_response_success_rate: float = 0.90
    low_approval_rate:         float = 0.50
    high_guard_intervention:   float = 0.30
    min_feedback_coverage:     float = 0.10


class RecommendationEngine:
    """Produces advisory improvements from measured evidence."""

    def __init__(self, thresholds: RecommendationThresholds | None = None) -> None:
        self.thresholds = thresholds or RecommendationThresholds()

    def recommend(
        self,
        metrics: list[MetricSummary],
        patterns: list[Pattern],
        *,
        feedback_coverage: float,
        total_incidents: int,
    ) -> list[Recommendation]:
        """Return recommendations, most urgent first."""
        by_name = {metric.name: metric for metric in metrics}
        recommendations: list[Recommendation] = []

        if total_incidents == 0:
            return []

        recommendations.extend(self._from_accuracy(by_name))
        recommendations.extend(self._from_operations(by_name))
        recommendations.extend(self._from_patterns(patterns))

        coverage_gap = self._feedback_gap(
            by_name, feedback_coverage, total_incidents
        )
        if coverage_gap is not None:
            recommendations.append(coverage_gap)

        order = {
            RecommendationPriority.CRITICAL: 0,
            RecommendationPriority.HIGH:     1,
            RecommendationPriority.MEDIUM:   2,
            RecommendationPriority.LOW:      3,
        }
        recommendations.sort(key=lambda r: order[r.priority])

        logger.info(
            "learning_recommendations_produced",
            extra={
                "count":             len(recommendations),
                "feedback_coverage": round(feedback_coverage, 3),
            },
        )
        return recommendations

    # ── Accuracy-driven (all require analyst ground truth) ───────────────────

    def _from_accuracy(
        self,
        metrics: dict[str, MetricSummary],
    ) -> list[Recommendation]:
        found: list[Recommendation] = []

        fp = metrics.get("false_positive_rate")
        if self._usable(fp) and fp.value >= self.thresholds.high_false_positive_rate:
            found.append(
                Recommendation(
                    recommendation_type=RecommendationType.RAISE_CONFIDENCE_THRESHOLD,
                    priority=RecommendationPriority.HIGH,
                    summary=(
                        f"False positive rate is {fp.value:.0%} across "
                        f"{fp.sample_size} labelled incident(s)"
                    ),
                    rationale=(
                        "Analysts are rejecting a large share of threat detections. "
                        "Benign traffic is being contained, which costs analyst time "
                        "and erodes trust in the platform's automated actions."
                    ),
                    suggested_change=(
                        "Raise the minimum confidence required for destructive "
                        "actions in config/response_policy.yaml (trust_tiers → "
                        "min_confidence), or tighten the DeterministicDecisionEngine "
                        "rule that is firing most often."
                    ),
                    evidence={"false_positive_rate": fp.value, "sample_size": fp.sample_size},
                    supporting_metric="false_positive_rate",
                )
            )
            # Pair the threshold change with a less disruptive default, so the
            # remaining false positives cost less when they do occur.
            found.append(
                Recommendation(
                    recommendation_type=RecommendationType.PREFER_LESS_DISRUPTIVE_ACTION,
                    priority=RecommendationPriority.MEDIUM,
                    summary="Prefer rate limiting over blocking while precision is low",
                    rationale=(
                        "While the false positive rate is elevated, a wrong RATE_LIMIT "
                        "degrades a legitimate user's throughput; a wrong BLOCK_IP cuts "
                        "them off entirely. The cheaper mistake is the better default."
                    ),
                    suggested_change=(
                        "Change the high-risk DeterministicDecisionEngine rules from "
                        "ActionType.BLOCK_IP to ActionType.RATE_LIMIT until precision "
                        "recovers."
                    ),
                    evidence={"false_positive_rate": fp.value},
                    supporting_metric="false_positive_rate",
                )
            )

        fn = metrics.get("false_negative_rate")
        if self._usable(fn) and fn.value >= self.thresholds.high_false_negative_rate:
            found.append(
                Recommendation(
                    recommendation_type=RecommendationType.LOWER_CONFIDENCE_THRESHOLD,
                    priority=RecommendationPriority.CRITICAL,
                    summary=(
                        f"False negative rate is {fn.value:.0%} — real threats are "
                        "being classified as benign"
                    ),
                    rationale=(
                        "A missed threat is the most expensive error this platform can "
                        "make: it produces no alert, no record, and no opportunity for "
                        "an analyst to catch it. This outranks false-positive tuning."
                    ),
                    suggested_change=(
                        "Lower the detection confidence threshold, and review the "
                        "INCONCLUSIVE handling in DeterministicDecisionEngine so "
                        "uncertain traffic reaches an analyst instead of being logged."
                    ),
                    evidence={"false_negative_rate": fn.value, "sample_size": fn.sample_size},
                    supporting_metric="false_negative_rate",
                )
            )

        accuracy = metrics.get("detection_accuracy")
        if self._usable(accuracy) and accuracy.value < self.thresholds.low_detection_accuracy:
            found.append(
                Recommendation(
                    recommendation_type=RecommendationType.RETRAIN_MODEL,
                    priority=RecommendationPriority.HIGH,
                    summary=(
                        f"Detection accuracy is {accuracy.value:.0%} over "
                        f"{accuracy.sample_size} labelled incident(s)"
                    ),
                    rationale=(
                        "Measured accuracy has fallen below the acceptable floor, which "
                        "usually indicates drift between the CICIDS2017 training "
                        "distribution and live traffic."
                    ),
                    suggested_change=(
                        "Export the labelled incidents as a supervised dataset and run "
                        "train.py. Do not deploy the result without comparing it against "
                        "the current model on a held-out set."
                    ),
                    evidence={"detection_accuracy": accuracy.value},
                    supporting_metric="detection_accuracy",
                )
            )

        decision_accuracy = metrics.get("decision_accuracy")
        if (
            self._usable(decision_accuracy)
            and decision_accuracy.value < self.thresholds.low_decision_accuracy
        ):
            found.append(
                Recommendation(
                    recommendation_type=RecommendationType.REVIEW_POLICY,
                    priority=RecommendationPriority.HIGH,
                    summary=(
                        f"Analysts disagreed with {1 - decision_accuracy.value:.0%} of "
                        "decisions"
                    ),
                    rationale=(
                        "Detection may be sound while the chosen response is wrong. This "
                        "points at the policy rule table rather than the model."
                    ),
                    suggested_change=(
                        "Review DeterministicDecisionEngine.RULES against the rejected "
                        "decisions; the rule names are recorded on every DecisionResult."
                    ),
                    evidence={"decision_accuracy": decision_accuracy.value},
                    supporting_metric="decision_accuracy",
                )
            )

        return found

    # ── Operational (measurable without ground truth) ────────────────────────

    def _from_operations(
        self,
        metrics: dict[str, MetricSummary],
    ) -> list[Recommendation]:
        found: list[Recommendation] = []

        success = metrics.get("response_success_rate")
        if self._usable(success) and success.value < self.thresholds.low_response_success_rate:
            found.append(
                Recommendation(
                    recommendation_type=RecommendationType.REVIEW_EXECUTOR,
                    priority=RecommendationPriority.HIGH,
                    summary=(
                        f"Only {success.value:.0%} of attempted actions succeeded"
                    ),
                    rationale=(
                        "Containment is being decided but not delivered. The platform "
                        "reports protection it did not actually apply."
                    ),
                    suggested_change=(
                        "Inspect the failing executor's attempt history via "
                        "GET /response/actions?status=FAILED and check its health_check()."
                    ),
                    evidence={"response_success_rate": success.value},
                    supporting_metric="response_success_rate",
                )
            )

        approval = metrics.get("approval_rate")
        if self._usable(approval) and approval.value < self.thresholds.low_approval_rate:
            found.append(
                Recommendation(
                    recommendation_type=RecommendationType.REVIEW_POLICY,
                    priority=RecommendationPriority.MEDIUM,
                    summary=(
                        f"Analysts rejected {1 - approval.value:.0%} of the actions "
                        "sent for approval"
                    ),
                    rationale=(
                        "The decision layer is routinely proposing actions analysts do "
                        "not want. Each rejection is wasted analyst attention."
                    ),
                    suggested_change=(
                        "Review which policy rules generate the rejected proposals and "
                        "either narrow their conditions or lower their action severity."
                    ),
                    evidence={"approval_rate": approval.value},
                    supporting_metric="approval_rate",
                )
            )

        guard = metrics.get("guard_intervention_rate")
        if self._usable(guard) and guard.value >= self.thresholds.high_guard_intervention:
            found.append(
                Recommendation(
                    recommendation_type=RecommendationType.TUNE_TRUST_TIER,
                    priority=RecommendationPriority.MEDIUM,
                    summary=(
                        f"The safety guard overrode {guard.value:.0%} of responses"
                    ),
                    rationale=(
                        "Frequent overrides mean the decision layer and the response "
                        "policy disagree. That is the guard working correctly, but the "
                        "disagreement itself is worth resolving — either the engine is "
                        "under-trusted or it is proposing actions it should not."
                    ),
                    suggested_change=(
                        "Compare guard_rule frequencies in GET /response/actions against "
                        "the engine_trust tiers in config/response_policy.yaml. Do not "
                        "raise a tier without reviewing the downgraded actions first."
                    ),
                    evidence={"guard_intervention_rate": guard.value},
                    supporting_metric="guard_intervention_rate",
                )
            )

        return found

    # ── Pattern-driven ────────────────────────────────────────────────────────

    def _from_patterns(self, patterns: list[Pattern]) -> list[Recommendation]:
        found: list[Recommendation] = []

        for pattern in patterns:
            if pattern.pattern_type is PatternType.RECURRING_INCIDENT:
                found.append(
                    Recommendation(
                        recommendation_type=RecommendationType.ADD_CONTAINMENT_RULE,
                        priority=RecommendationPriority.HIGH,
                        summary=pattern.summary,
                        rationale=(
                            "The same entity is producing the same threat repeatedly, "
                            "which suggests earlier containment expired, was reverted, "
                            "or was never actually applied."
                        ),
                        suggested_change=(
                            "Consider a durable block for "
                            f"{', '.join(pattern.entities) or 'the affected entity'}, "
                            "or extend duration_seconds for this action class."
                        ),
                        evidence=pattern.evidence,
                        supporting_patterns=[pattern.pattern_type],
                    )
                )
            elif pattern.pattern_type is PatternType.REPEAT_ATTACKER:
                found.append(
                    Recommendation(
                        recommendation_type=RecommendationType.ADD_CONTAINMENT_RULE,
                        priority=RecommendationPriority.MEDIUM,
                        summary=pattern.summary,
                        rationale=(
                            "A single entity is responsible for a disproportionate share "
                            "of incidents. A standing rule would stop re-deciding the "
                            "same case."
                        ),
                        suggested_change=(
                            "Consider adding "
                            f"{', '.join(pattern.entities) or 'the entity'} to a perimeter "
                            "denylist after analyst review."
                        ),
                        evidence=pattern.evidence,
                        supporting_patterns=[pattern.pattern_type],
                    )
                )
            elif pattern.pattern_type is PatternType.REPEATED_RESPONSE_FAILURE:
                found.append(
                    Recommendation(
                        recommendation_type=RecommendationType.REVIEW_EXECUTOR,
                        priority=RecommendationPriority.HIGH,
                        summary=pattern.summary,
                        rationale=(
                            "A specific action keeps failing against a specific target, "
                            "which points at an integration fault rather than policy."
                        ),
                        suggested_change=(
                            "Check the executor named in the evidence and the target's "
                            "reachability before re-attempting."
                        ),
                        evidence=pattern.evidence,
                        supporting_patterns=[pattern.pattern_type],
                    )
                )
            elif pattern.pattern_type is PatternType.APPROVAL_BOTTLENECK:
                found.append(
                    Recommendation(
                        recommendation_type=RecommendationType.REVIEW_POLICY,
                        priority=RecommendationPriority.MEDIUM,
                        summary=pattern.summary,
                        rationale=(
                            "Actions are waiting on approvals that never arrive, so the "
                            "containment was decided but never delivered."
                        ),
                        suggested_change=(
                            "Either staff the approval queue or narrow which rules set "
                            "requires_approval=True. Unreviewed proposals protect nobody."
                        ),
                        evidence=pattern.evidence,
                        supporting_patterns=[pattern.pattern_type],
                    )
                )

        return found

    # ── Evidence gap ──────────────────────────────────────────────────────────

    def _feedback_gap(
        self,
        metrics: dict[str, MetricSummary],
        feedback_coverage: float,
        total_incidents: int,
    ) -> Recommendation | None:
        """Emitted when ground-truth metrics could not be computed.

        This is the recommendation that replaces every accuracy-driven rule
        when the labels are not there — the honest output is "we cannot tell
        you yet, here is how to make us able to".
        """
        blocked = [
            name for name in (
                "false_positive_rate",
                "false_negative_rate",
                "detection_accuracy",
                "decision_accuracy",
            )
            if not self._usable(metrics.get(name))
        ]
        if not blocked:
            return None

        return Recommendation(
            recommendation_type=RecommendationType.COLLECT_MORE_FEEDBACK,
            priority=(
                RecommendationPriority.HIGH
                if feedback_coverage < self.thresholds.min_feedback_coverage
                else RecommendationPriority.MEDIUM
            ),
            summary=(
                f"Analyst feedback covers {feedback_coverage:.0%} of "
                f"{total_incidents} incident(s); "
                f"{len(blocked)} accuracy metric(s) cannot be computed"
            ),
            rationale=(
                "The platform cannot measure its own correctness. A confident wrong "
                "answer is indistinguishable from a confident right one, so false "
                "positives, false negatives, and accuracy are only knowable from "
                "analyst verdicts. Until coverage improves, no tuning recommendation "
                "based on accuracy can be made responsibly."
            ),
            suggested_change=(
                "Have analysts rule on closed incidents via "
                "POST /learning/feedback. Labelling even a small random sample of "
                "each day's incidents makes the accuracy metrics usable."
            ),
            evidence={
                "feedback_coverage":  feedback_coverage,
                "total_incidents":    total_incidents,
                "unavailable_metrics": blocked,
            },
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _usable(metric: MetricSummary | None) -> bool:
        """True when a metric may be used as the basis for a recommendation."""
        return (
            metric is not None
            and metric.sufficient_data
            and metric.value is not None
        )
