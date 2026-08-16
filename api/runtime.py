"""Platform singletons and their construction.

Everything the API layer needs that outlives a request lives on the `platform`
object here: model artifacts, the LangGraph runtime, the memory provider, and
the response/learning/ingestion services.

WHY A SINGLE OBJECT RATHER THAN MODULE GLOBALS
----------------------------------------------
These used to be a dozen module-level names in app.py, rebound inside
`ensure_runtime()` via a three-line `global` statement. Any module that did
`from app import RUNTIME` captured whatever the value was at import time and
never saw the real one. Attribute access on one object cannot go stale, so
routers read `platform.runtime` and always get the current binding.

Construction is lazy and idempotent: `ensure_runtime()` builds everything on
first call and returns immediately afterwards.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

ARTIFACT_DIR = os.path.abspath(
    os.environ.get(
        "ARTIFACT_DIR",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "artifacts"),
    )
)

ATTACK_PROFILES_PATH = os.path.join(ARTIFACT_DIR, "attack_profiles.json")


@dataclass
class PlatformRuntime:
    """Live platform components. Populated by `ensure_runtime()`."""

    artifacts: Any = None
    model: Any = None
    scaler: Any = None
    label_encoder: Any = None
    feature_columns: Any = None

    runtime: Any = None
    memory_provider: Any = None
    response_agent: Any = None
    approval_store: Any = None
    response_policy: Any = None
    learning_agent: Any = None
    ingestion_service: Any = None

    # Reason the last initialization attempt failed, surfaced by /health.
    init_error: str | None = None

    attack_profiles: dict[str, dict[str, float]] = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return self.runtime is not None and self.artifacts is not None


platform = PlatformRuntime()


def ensure_runtime() -> Any:
    """Build the platform on first call. Returns the graph runtime, or None.

    Returns None when artifacts could not be loaded — detection is then
    disabled and `/health` reports 503 with `platform.init_error`. This is
    deliberate: a security platform that cannot load its model must not
    pretend it is running.
    """
    if platform.runtime is not None:
        return platform.runtime

    # Imported here rather than at module scope: importing inference pulls in
    # ~100 MB of model artifacts and sentence-transformers pulls in torch.
    # Keeping them out of import time lets tests import the API layer cheaply.
    from adapters.detection.ids_adapter import IDSDetectionAdapter
    from adapters.response import build_default_registry
    from agents.analysis.analysis_agent import AnalysisAgent
    from agents.coordinator.coordinator_agent import DEFAULT_MAX_ITERATIONS, CoordinatorAgent
    from agents.decision.decision_agent import DecisionAgent
    from agents.decision.deterministic import DeterministicDecisionEngine
    from agents.detection.detection_agent import DetectionAgent
    from agents.learning.learning_agent import LearningAgent
    from agents.response.approval import InMemoryApprovalStore, MemoryApprovalStore
    from agents.response.config import ResponsePolicyConfig
    from agents.response.guard import ActionGuard
    from agents.response.response_agent import ResponseAgent
    from ai_engine.deterministic import DeterministicRuleEngine
    from graph.builder import GraphBuilder
    from graph.runtime import GraphRuntime
    from inference import IDSArtifacts, resolve_model_path
    from ingestion.service import IngestionService
    from memory.qdrant_sqlite import QdrantSqliteMemoryProvider

    try:
        model_path = resolve_model_path(ARTIFACT_DIR)
        print(f"[INFO] Using model artifact: {model_path}")

        platform.artifacts = IDSArtifacts(
            model_path=model_path,
            scaler_path=os.path.join(ARTIFACT_DIR, "scaler.pkl"),
            le_path=os.path.join(ARTIFACT_DIR, "label_encoder.pkl"),
            feat_path=os.path.join(ARTIFACT_DIR, "feature_columns.json"),
            iforest_path=os.path.join(ARTIFACT_DIR, "iforest.pkl"),
            ae_path=os.path.join(ARTIFACT_DIR, "autoencoder.pkl"),
            thresholds_path=os.path.join(ARTIFACT_DIR, "anomaly_thresholds.json"),
        )
        platform.model           = platform.artifacts.model
        platform.scaler          = platform.artifacts.scaler
        platform.label_encoder   = platform.artifacts.le
        platform.feature_columns = platform.artifacts.feature_cols

        adapter = IDSDetectionAdapter(artifacts=platform.artifacts)

        try:
            platform.memory_provider = QdrantSqliteMemoryProvider(
                db_path=os.environ.get("MEMORY_DB_PATH", "memory_metadata.db"),
                qdrant_path=os.environ.get("MEMORY_QDRANT_PATH", "qdrant_db"),
            )
        except Exception as exc:
            platform.memory_provider = None
            print(f"[WARN] Memory provider unavailable, continuing without persisted memory: {exc}")

        # Response layer: policy from config/response_policy.yaml, falling back
        # to fail-closed defaults. Only simulation-safe executors are
        # registered — nothing here touches real infrastructure until an
        # operator registers a real integration.
        platform.response_policy = ResponsePolicyConfig.load()
        platform.approval_store = (
            MemoryApprovalStore(platform.memory_provider)
            if platform.memory_provider is not None
            else InMemoryApprovalStore()
        )
        platform.response_agent = ResponseAgent(
            build_default_registry(),
            guard=ActionGuard(platform.response_policy),
            approval_store=platform.approval_store,
            memory_provider=platform.memory_provider,
            config=platform.response_policy,
        )

        builder = GraphBuilder()
        builder.register_node(
            "detection", DetectionAgent(adapter, memory_provider=platform.memory_provider)
        )
        builder.register_node(
            "analysis",
            AnalysisAgent(DeterministicRuleEngine(), memory_provider=platform.memory_provider),
        )
        builder.register_node(
            "decision",
            DecisionAgent(DeterministicDecisionEngine(), memory_provider=platform.memory_provider),
        )
        builder.register_node("response", platform.response_agent)

        # LearningAgent runs over history, not per event, so it is deliberately
        # NOT a pipeline node — that would re-derive platform-wide metrics on
        # every single flow.
        platform.learning_agent = (
            LearningAgent(platform.memory_provider)
            if platform.memory_provider is not None
            else None
        )

        # The coordinator turns the linear chain into a drained work queue.
        # Without it each run processes exactly one security event and silently
        # drops the rest, because every agent handles one pending item per call.
        coordinator = CoordinatorAgent()
        builder.register_coordinator(
            "coordinator", coordinator, coordinator.route,
            routable_targets=coordinator.routable_targets,
        )

        platform.runtime = GraphRuntime(builder=builder)

        # Live ingestion. Constructed but NOT started — beginning a packet
        # capture is a privileged act that must be an explicit operator
        # decision, never a side effect of the server booting.
        platform.ingestion_service = IngestionService(
            platform.runtime, coordinator_budget=DEFAULT_MAX_ITERATIONS
        )

        platform.attack_profiles = load_attack_profiles()
        platform.init_error = None
        print("[INFO] Model artifacts & LangGraph ML runtime created and registered successfully.")
    except Exception as exc:
        platform.init_error = f"{type(exc).__name__}: {exc}"
        print(f"[ERROR] Could not initialize GraphRuntime: {exc}")

    return platform.runtime


def shutdown() -> None:
    """Release resources held by the platform. Safe to call more than once."""
    if platform.ingestion_service is not None:
        try:
            if platform.ingestion_service.is_running():
                platform.ingestion_service.stop()
        except Exception as exc:
            print(f"[WARN] Ingestion did not stop cleanly: {exc}")

    provider = platform.memory_provider
    close = getattr(provider, "close", None)
    if callable(close):
        try:
            close()
        except Exception as exc:
            print(f"[WARN] Memory provider did not close cleanly: {exc}")


# ── Simulation profiles ───────────────────────────────────────────────────────

# Class label -> the scenario name shown in the dashboard.
PROFILE_DISPLAY_NAMES = {
    "BENIGN":     "Normal HTTP Traffic",
    "BOTNET":     "Botnet C2 Beaconing",
    "BRUTEFORCE": "SSH/FTP Brute Force",
    "DDOS":       "Distributed Denial of Service",
    "DOS":        "Denial of Service (Hulk/GoldenEye)",
    "PORTSCAN":   "Port Scan Reconnaissance",
    "WEBATTACK":  "Web Attack (SQLi / XSS)",
}


def load_attack_profiles() -> dict[str, dict[str, float]]:
    """Load per-class median flow profiles, keyed by display name.

    Derived from the real training data by scripts/build_attack_profiles.py.
    Returns an empty dict when the artifact is absent; the simulation endpoint
    then reports 503 rather than falling back to fabricated vectors.
    """
    import json

    try:
        with open(ATTACK_PROFILES_PATH, encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        print(
            f"[WARN] {ATTACK_PROFILES_PATH} not found. The simulation endpoint "
            "is disabled. Generate it with: python scripts/build_attack_profiles.py"
        )
        return {}
    except Exception as exc:
        print(f"[WARN] Could not read attack profiles: {exc}")
        return {}

    profiles = payload.get("profiles", {})
    named = {
        PROFILE_DISPLAY_NAMES.get(label, label): features
        for label, features in profiles.items()
    }
    print(
        f"[INFO] Loaded {len(named)} simulation profiles "
        f"({payload.get('_statistic', 'unknown')} over "
        f"{payload.get('_source_dataset', 'unknown dataset')})."
    )
    return named
