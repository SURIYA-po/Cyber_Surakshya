"""LearningAgent reports, metrics, and the analyst feedback loop.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError

from agents.learning.exceptions import FeedbackStoreError
from agents.learning.learning_agent import LearningAgent
from api.runtime import ensure_runtime, platform
from cyber_surakshya.platform.schemas.learning_report import AnalystVerdict

router = APIRouter(tags=["learning"])


def _require_learning_agent() -> LearningAgent:
    ensure_runtime()
    if platform.learning_agent is None:
        raise HTTPException(
            status_code=503,
            detail="Learning agent unavailable: no memory provider is configured.",
        )
    return platform.learning_agent


@router.post("/learning/analyze")
def run_learning_analysis(limit: int = 1000, persist: bool = True):
    """Run a learning cycle over incident history and return the report."""
    agent = _require_learning_agent()
    report = agent.analyze(limit=limit, persist=persist)
    return JSONResponse(content=report.model_dump(mode="json"))


@router.get("/learning/report")
def get_latest_learning_report():
    """Return the most recent persisted report, without recomputing."""
    agent = _require_learning_agent()
    report = agent.latest_report()
    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No learning report has been generated yet. POST /learning/analyze first.",
        )
    return JSONResponse(content=report)


@router.get("/learning/reports")
def list_learning_reports(limit: int = 20):
    """Return persisted reports newest first, for trend tracking."""
    return JSONResponse(content=_require_learning_agent().list_reports(limit=limit))


@router.get("/learning/metrics")
def get_learning_metrics(limit: int = 1000):
    """Return just the metrics, each with its evidence base."""
    report = _require_learning_agent().analyze(limit=limit, persist=False)
    return JSONResponse(content={
        "total_incidents":   report.total_incidents,
        "labeled_incidents": report.labeled_incidents,
        "feedback_coverage": report.feedback_coverage,
        "min_sample_size":   report.min_sample_size,
        "metrics":           [m.model_dump(mode="json") for m in report.metrics],
    })


@router.get("/learning/patterns")
def get_learning_patterns(limit: int = 1000):
    """Return discovered patterns across incident history."""
    report = _require_learning_agent().analyze(limit=limit, persist=False)
    return JSONResponse(
        content=[p.model_dump(mode="json") for p in report.patterns]
    )


@router.get("/learning/recommendations")
def get_learning_recommendations(limit: int = 1000):
    """Return ranked recommendations. Advisory only — nothing is applied."""
    report = _require_learning_agent().analyze(limit=limit, persist=False)
    return JSONResponse(
        content=[r.model_dump(mode="json") for r in report.recommendations]
    )


@router.post("/learning/feedback")
def record_analyst_feedback(
    detection_id: str,
    verdict: str,
    analyst: str = "analyst",
    decision_id: str | None = None,
    notes: str | None = None,
    actual_label: str | None = None,
):
    """Record an analyst verdict on an incident.

    This is the platform's only source of ground truth: false positives,
    false negatives, and accuracy cannot be computed without it.
    """
    agent = _require_learning_agent()
    try:
        resolved = AnalystVerdict(verdict.upper())
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown verdict {verdict!r}. Expected one of: "
                f"{[v.value for v in AnalystVerdict]}"
            ),
        )
    try:
        feedback = agent.record_feedback(
            detection_id=detection_id,
            verdict=resolved,
            analyst=analyst,
            decision_id=decision_id,
            notes=notes,
            actual_label=actual_label,
        )
    except PydanticValidationError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feedback: {exc.errors()[0].get('msg', str(exc))}",
        )
    except FeedbackStoreError as exc:
        # Surfaced rather than swallowed: silently losing a verdict would
        # corrupt every accuracy metric derived from it.
        raise HTTPException(status_code=502, detail=str(exc))
    return JSONResponse(content=feedback.model_dump(mode="json"))


@router.get("/learning/feedback")
def list_analyst_feedback(limit: int = 200):
    """Return recorded analyst verdicts, newest first."""
    return JSONResponse(content=[
        f.model_dump(mode="json")
        for f in _require_learning_agent().list_feedback(limit=limit)
    ])
