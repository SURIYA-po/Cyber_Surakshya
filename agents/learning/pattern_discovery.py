"""Module 3 — Pattern Discovery.

Finds recurring structures across incident history: repeat attackers, frequent
threats, repeated response failures, common attack paths, recurring incidents,
approval bottlenecks, and guard friction.

Deliberately arithmetic, not statistical. Frequency counting over a few
hundred incidents is honest and explainable; clustering or anomaly scoring at
this sample size would produce confident-looking noise that the
RecommendationEngine would then turn into firewall changes.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime

from agents.learning.outcome_collector import IncidentHistory
from cyber_surakshya.platform.schemas.learning_report import Pattern, PatternType

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PatternThresholds:
    """Minimum occurrences before a repetition counts as a pattern.

    Data, not code: tuning these for a noisier network is a constructor
    argument, not an edit.
    """

    repeat_attacker:      int = 3
    frequent_threat:      int = 5
    response_failure:     int = 2
    attack_path:          int = 3
    recurring_incident:   int = 3
    pending_approvals:    int = 3
    guard_intervention:   int = 3


class PatternDiscovery:
    """Frequency analysis over incident history."""

    def __init__(self, thresholds: PatternThresholds | None = None) -> None:
        self.thresholds = thresholds or PatternThresholds()

    def discover(self, incidents: list[IncidentHistory]) -> list[Pattern]:
        """Return every pattern meeting its threshold, most frequent first."""
        if not incidents:
            return []

        patterns: list[Pattern] = [
            *self._repeat_attackers(incidents),
            *self._frequent_threats(incidents),
            *self._repeated_response_failures(incidents),
            *self._common_attack_paths(incidents),
            *self._recurring_incidents(incidents),
            *self._approval_bottleneck(incidents),
            *self._guard_friction(incidents),
        ]
        patterns.sort(key=lambda p: p.occurrences, reverse=True)

        logger.info(
            "learning_patterns_discovered",
            extra={"incidents": len(incidents), "patterns": len(patterns)},
        )
        return patterns

    # ── Patterns ──────────────────────────────────────────────────────────────

    def _repeat_attackers(self, incidents: list[IncidentHistory]) -> list[Pattern]:
        """Entities responsible for repeated threat incidents."""
        by_entity: dict[str, list[IncidentHistory]] = defaultdict(list)
        for incident in incidents:
            if incident.is_threat and incident.entity_id:
                by_entity[incident.entity_id].append(incident)

        found: list[Pattern] = []
        for entity, group in by_entity.items():
            if len(group) < self.thresholds.repeat_attacker:
                continue
            labels = Counter(i.predicted_label for i in group)
            first, last = self._window(group)
            found.append(
                Pattern(
                    pattern_type=PatternType.REPEAT_ATTACKER,
                    summary=(
                        f"{entity} generated {len(group)} threat incident(s) "
                        f"({', '.join(f'{k}×{v}' for k, v in labels.most_common(3))})"
                    ),
                    occurrences=len(group),
                    entities=[entity],
                    first_seen=first,
                    last_seen=last,
                    evidence={"labels": dict(labels)},
                )
            )
        return found

    def _frequent_threats(self, incidents: list[IncidentHistory]) -> list[Pattern]:
        """Threat labels that dominate the history."""
        labels = Counter(i.predicted_label for i in incidents if i.is_threat)
        found: list[Pattern] = []
        for label, count in labels.items():
            if count < self.thresholds.frequent_threat:
                continue
            group = [i for i in incidents if i.predicted_label == label]
            first, last = self._window(group)
            entities = sorted({i.entity_id for i in group if i.entity_id})
            found.append(
                Pattern(
                    pattern_type=PatternType.FREQUENT_THREAT,
                    summary=(
                        f"{label} accounts for {count} incident(s) across "
                        f"{len(entities)} distinct entity/entities"
                    ),
                    occurrences=count,
                    entities=entities[:20],
                    first_seen=first,
                    last_seen=last,
                    evidence={"label": label, "distinct_entities": len(entities)},
                )
            )
        return found

    def _repeated_response_failures(
        self,
        incidents: list[IncidentHistory],
    ) -> list[Pattern]:
        """Actions that keep failing — usually a broken integration."""
        failures: Counter[tuple[str, str]] = Counter()
        executors: dict[tuple[str, str], set[str]] = defaultdict(set)
        for incident in incidents:
            for response in incident.responses:
                if response.get("status") != "FAILED":
                    continue
                key = (
                    str(response.get("action_type", "UNKNOWN")),
                    str(response.get("target_value", "UNKNOWN")),
                )
                failures[key] += 1
                if response.get("executor_name"):
                    executors[key].add(str(response["executor_name"]))

        found: list[Pattern] = []
        for (action, target), count in failures.items():
            if count < self.thresholds.response_failure:
                continue
            found.append(
                Pattern(
                    pattern_type=PatternType.REPEATED_RESPONSE_FAILURE,
                    summary=(
                        f"{action} on {target} failed {count} time(s)"
                    ),
                    occurrences=count,
                    entities=[target],
                    evidence={
                        "action_type": action,
                        "executors":   sorted(executors[(action, target)]),
                    },
                )
            )
        return found

    def _common_attack_paths(self, incidents: list[IncidentHistory]) -> list[Pattern]:
        """Frequent threat-label → chosen-action pairings."""
        paths: Counter[tuple[str, str]] = Counter()
        for incident in incidents:
            if not incident.is_threat or not incident.action_type:
                continue
            paths[(incident.predicted_label, incident.action_type)] += 1

        found: list[Pattern] = []
        for (label, action), count in paths.items():
            if count < self.thresholds.attack_path:
                continue
            found.append(
                Pattern(
                    pattern_type=PatternType.COMMON_ATTACK_PATH,
                    summary=f"{label} was handled with {action} {count} time(s)",
                    occurrences=count,
                    evidence={"label": label, "action_type": action},
                )
            )
        return found

    def _recurring_incidents(self, incidents: list[IncidentHistory]) -> list[Pattern]:
        """The same entity hit by the same threat repeatedly.

        Distinct from a repeat attacker: this is the same attack recurring,
        which usually means the containment is not holding.
        """
        pairs: dict[tuple[str, str], list[IncidentHistory]] = defaultdict(list)
        for incident in incidents:
            if incident.is_threat and incident.entity_id:
                pairs[(incident.entity_id, incident.predicted_label)].append(incident)

        found: list[Pattern] = []
        for (entity, label), group in pairs.items():
            if len(group) < self.thresholds.recurring_incident:
                continue
            first, last = self._window(group)
            found.append(
                Pattern(
                    pattern_type=PatternType.RECURRING_INCIDENT,
                    summary=(
                        f"{entity} triggered {label} {len(group)} time(s) — "
                        "prior containment may not be holding"
                    ),
                    occurrences=len(group),
                    entities=[entity],
                    first_seen=first,
                    last_seen=last,
                    evidence={"label": label},
                )
            )
        return found

    def _approval_bottleneck(self, incidents: list[IncidentHistory]) -> list[Pattern]:
        """Actions stuck awaiting an analyst who never ruled."""
        stuck = [
            incident for incident in incidents
            if incident.responses
            and incident.terminal_response is None
            and incident.approval is None
        ]
        if len(stuck) < self.thresholds.pending_approvals:
            return []
        first, last = self._window(stuck)
        return [
            Pattern(
                pattern_type=PatternType.APPROVAL_BOTTLENECK,
                summary=(
                    f"{len(stuck)} action(s) are awaiting approval with no "
                    "analyst ruling recorded"
                ),
                occurrences=len(stuck),
                entities=sorted({i.entity_id for i in stuck if i.entity_id})[:20],
                first_seen=first,
                last_seen=last,
                evidence={
                    "action_types": sorted({
                        str(i.action_type) for i in stuck if i.action_type
                    })
                },
            )
        ]

    def _guard_friction(self, incidents: list[IncidentHistory]) -> list[Pattern]:
        """Decision engines whose actions the safety guard keeps overriding."""
        by_engine: Counter[str] = Counter()
        totals: Counter[str] = Counter()
        rules: dict[str, Counter[str]] = defaultdict(Counter)
        for incident in incidents:
            for response in incident.responses:
                engine = str(response.get("decision_engine", "UNKNOWN"))
                totals[engine] += 1
                if str(response.get("status", "")) in {"DOWNGRADED", "BLOCKED_BY_GUARD"}:
                    by_engine[engine] += 1
                    rules[engine][str(response.get("guard_rule", "unknown"))] += 1

        found: list[Pattern] = []
        for engine, count in by_engine.items():
            if count < self.thresholds.guard_intervention:
                continue
            total = totals[engine] or 1
            found.append(
                Pattern(
                    pattern_type=PatternType.GUARD_FRICTION,
                    summary=(
                        f"the safety guard overrode {engine} on {count} of "
                        f"{total} response(s)"
                    ),
                    occurrences=count,
                    confidence=min(1.0, count / total),
                    evidence={
                        "decision_engine": engine,
                        "total_responses": total,
                        "top_rules":       dict(rules[engine].most_common(3)),
                    },
                )
            )
        return found

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _window(
        incidents: list[IncidentHistory],
    ) -> tuple[datetime | None, datetime | None]:
        stamps = sorted(i.detected_at for i in incidents if i.detected_at)
        if not stamps:
            return None, None
        return stamps[0], stamps[-1]
