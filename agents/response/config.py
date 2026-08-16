"""Response policy configuration — loading, validation, and fail-closed defaults.

The policy that authorises real-world actions is data, not code. This module
loads config/response_policy.yaml into frozen dataclasses.

FAIL-CLOSED CONTRACT: every failure path — missing file, unreadable file,
malformed YAML, missing PyYAML, unknown enum value — yields the built-in
defaults below, which are the strictest configuration the platform supports.
A configuration problem must never widen what the platform is allowed to do.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import socket
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from cyber_surakshya.platform.actions.action_type import ActionType
from cyber_surakshya.platform.schemas.response_result import EngineTrustTier

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "config" / "response_policy.yaml"


# ── Policy fragments ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TrustTierPolicy:
    """What a given engine trust tier is permitted to do."""

    destructive_allowed: bool
    min_confidence:      float


@dataclass(frozen=True)
class BlastRadiusPolicy:
    """Bounds on how much damage one run — or one engine — can cause."""

    max_destructive_per_correlation:           int = 3
    max_destructive_per_target_window_seconds: int = 900
    global_destructive_per_minute:             int = 10


@dataclass(frozen=True)
class ProtectedTargets:
    """Entities that must never be acted upon."""

    cidrs: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in self.cidrs:
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning(
                    "response_policy_invalid_protected_cidr",
                    extra={"cidr": cidr},
                )
        object.__setattr__(self, "_networks", tuple(networks))
        object.__setattr__(
            self, "_hosts_lower", frozenset(h.strip().lower() for h in self.hosts if h.strip())
        )

    def covers_ip(self, value: str) -> bool:
        """Return True when an address falls inside a protected range."""
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in network for network in getattr(self, "_networks", ()))

    def covers_host(self, value: str) -> bool:
        """Return True when a hostname is explicitly protected."""
        return value.strip().lower() in getattr(self, "_hosts_lower", frozenset())


# ── Built-in fail-closed defaults ─────────────────────────────────────────────

_DEFAULT_TRUST_TIERS: dict[EngineTrustTier, TrustTierPolicy] = {
    EngineTrustTier.DETERMINISTIC: TrustTierPolicy(True,  0.70),
    EngineTrustTier.AI_SUPERVISED: TrustTierPolicy(False, 0.90),
    EngineTrustTier.AI_AUTONOMOUS: TrustTierPolicy(True,  0.95),
    # min_confidence > 1.0 is unsatisfiable, so an unregistered engine is
    # downgraded even if destructive_allowed were flipped by mistake.
    EngineTrustTier.UNKNOWN:       TrustTierPolicy(False, 1.01),
}

_DEFAULT_DESTRUCTIVE: frozenset[ActionType] = frozenset({
    ActionType.BLOCK_IP,
    ActionType.ISOLATE_HOST,
    ActionType.TERMINATE_PROCESS,
    ActionType.QUARANTINE_FILE,
    ActionType.REVOKE_CREDENTIALS,
    ActionType.RATE_LIMIT,
})

_DEFAULT_PROTECTED_CIDRS: tuple[str, ...] = (
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "0.0.0.0/32",
    "::1/128",
    "fe80::/10",
)


@dataclass(frozen=True)
class ResponsePolicyConfig:
    """Complete authorisation policy for the response layer."""

    dry_run: bool = False

    engine_trust: dict[str, EngineTrustTier] = field(
        default_factory=lambda: {"DeterministicDecisionEngine": EngineTrustTier.DETERMINISTIC}
    )
    trust_tiers: dict[EngineTrustTier, TrustTierPolicy] = field(
        default_factory=lambda: dict(_DEFAULT_TRUST_TIERS)
    )

    destructive_actions: frozenset[ActionType] = _DEFAULT_DESTRUCTIVE
    downgrade_action:    ActionType            = ActionType.NOTIFY_SOC

    protected_targets: ProtectedTargets = field(
        default_factory=lambda: ProtectedTargets(cidrs=_DEFAULT_PROTECTED_CIDRS)
    )
    approval_required_asset_criticality: frozenset[str] = frozenset({"CRITICAL"})

    blast_radius: BlastRadiusPolicy = field(default_factory=BlastRadiusPolicy)

    idempotency_window_seconds: int = 900
    execution_timeout_seconds:  int = 30
    max_retries:                int = 2
    min_action_duration_seconds: int = 60
    max_action_duration_seconds: int = 86400

    # Set when the config came from built-in defaults rather than a file.
    loaded_from_defaults: bool = True
    source_path:          str | None = None

    def is_destructive(self, action_type: ActionType) -> bool:
        """Return True when a verb changes network, endpoint, or identity state."""
        return action_type in self.destructive_actions

    def tier_policy(self, tier: EngineTrustTier) -> TrustTierPolicy:
        """Return the policy for a tier, defaulting to UNKNOWN's strict policy."""
        return self.trust_tiers.get(tier, _DEFAULT_TRUST_TIERS[EngineTrustTier.UNKNOWN])

    # ── Loading ───────────────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> ResponsePolicyConfig:
        """Load policy from YAML, falling back to fail-closed defaults.

        Never raises. A configuration problem degrades the platform toward
        doing less, never more.
        """
        config_path = Path(path) if path else Path(
            os.environ.get("RESPONSE_POLICY_PATH", DEFAULT_CONFIG_PATH)
        )
        try:
            import yaml  # imported lazily so PyYAML stays an optional dependency
        except ImportError:
            logger.warning(
                "response_policy_pyyaml_missing",
                extra={"path": str(config_path)},
            )
            return cls()

        if not config_path.is_file():
            logger.warning(
                "response_policy_file_missing_using_defaults",
                extra={"path": str(config_path)},
            )
            return cls()

        try:
            raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if not isinstance(raw, dict):
                raise ValueError("Response policy root must be a mapping.")
        except Exception as exc:
            logger.error(
                "response_policy_load_failed_using_defaults",
                extra={"path": str(config_path), "error": str(exc)},
            )
            return cls()

        try:
            config = cls._from_mapping(raw, config_path)
        except Exception as exc:
            logger.error(
                "response_policy_parse_failed_using_defaults",
                extra={"path": str(config_path), "error": str(exc)},
            )
            return cls()

        if raw.get("protected_targets", {}).get("gateways_auto_detect", False):
            config = config._with_autodetected_gateways()

        logger.info(
            "response_policy_loaded",
            extra={
                "path":                str(config_path),
                "dry_run":             config.dry_run,
                "registered_engines":  len(config.engine_trust),
                "destructive_actions": len(config.destructive_actions),
            },
        )
        return config

    @classmethod
    def _from_mapping(cls, raw: dict[str, Any], path: Path) -> ResponsePolicyConfig:
        """Build a config from parsed YAML. Unknown values fall back per field."""
        defaults = cls()

        engine_trust: dict[str, EngineTrustTier] = {}
        for name, tier_name in (raw.get("engine_trust") or {}).items():
            try:
                engine_trust[str(name)] = EngineTrustTier(str(tier_name).upper())
            except ValueError:
                logger.warning(
                    "response_policy_unknown_trust_tier",
                    extra={"engine": name, "tier": tier_name},
                )

        trust_tiers = dict(_DEFAULT_TRUST_TIERS)
        for tier_name, spec in (raw.get("trust_tiers") or {}).items():
            try:
                tier = EngineTrustTier(str(tier_name).upper())
            except ValueError:
                logger.warning(
                    "response_policy_unknown_tier_definition",
                    extra={"tier": tier_name},
                )
                continue
            trust_tiers[tier] = TrustTierPolicy(
                destructive_allowed=bool(spec.get("destructive_allowed", False)),
                min_confidence=float(spec.get("min_confidence", 1.01)),
            )
        # UNKNOWN is not operator-overridable: fail-closed is a platform
        # invariant, not a preference.
        trust_tiers[EngineTrustTier.UNKNOWN] = _DEFAULT_TRUST_TIERS[EngineTrustTier.UNKNOWN]

        destructive: set[ActionType] = set()
        for name in raw.get("destructive_actions") or []:
            try:
                destructive.add(ActionType(str(name).upper()))
            except ValueError:
                logger.warning(
                    "response_policy_unknown_destructive_action",
                    extra={"action": name},
                )
        if not destructive:
            destructive = set(_DEFAULT_DESTRUCTIVE)

        try:
            downgrade = ActionType(str(raw.get("downgrade_action", "NOTIFY_SOC")).upper())
        except ValueError:
            downgrade = defaults.downgrade_action
        if downgrade in destructive:
            # A downgrade must reduce impact. Silently accepting a destructive
            # substitute would turn the safety net into an escalation path.
            logger.error(
                "response_policy_downgrade_action_is_destructive",
                extra={"action": downgrade.value},
            )
            downgrade = ActionType.NOTIFY_SOC

        protected_raw = raw.get("protected_targets") or {}
        cidrs = tuple(str(c) for c in (protected_raw.get("cidrs") or _DEFAULT_PROTECTED_CIDRS))
        hosts = tuple(str(h) for h in (protected_raw.get("hosts") or []))

        blast_raw = raw.get("blast_radius") or {}
        blast = BlastRadiusPolicy(
            max_destructive_per_correlation=int(
                blast_raw.get("max_destructive_per_correlation",
                              defaults.blast_radius.max_destructive_per_correlation)
            ),
            max_destructive_per_target_window_seconds=int(
                blast_raw.get("max_destructive_per_target_window_seconds",
                              defaults.blast_radius.max_destructive_per_target_window_seconds)
            ),
            global_destructive_per_minute=int(
                blast_raw.get("global_destructive_per_minute",
                              defaults.blast_radius.global_destructive_per_minute)
            ),
        )

        criticality = frozenset(
            str(c).upper()
            for c in (raw.get("approval_required_asset_criticality")
                      or defaults.approval_required_asset_criticality)
        )

        return cls(
            dry_run=bool(raw.get("dry_run", False)),
            engine_trust=engine_trust,
            trust_tiers=trust_tiers,
            destructive_actions=frozenset(destructive),
            downgrade_action=downgrade,
            protected_targets=ProtectedTargets(cidrs=cidrs, hosts=hosts),
            approval_required_asset_criticality=criticality,
            blast_radius=blast,
            idempotency_window_seconds=int(
                raw.get("idempotency_window_seconds", defaults.idempotency_window_seconds)
            ),
            execution_timeout_seconds=int(
                raw.get("execution_timeout_seconds", defaults.execution_timeout_seconds)
            ),
            max_retries=int(raw.get("max_retries", defaults.max_retries)),
            min_action_duration_seconds=int(
                raw.get("min_action_duration_seconds", defaults.min_action_duration_seconds)
            ),
            max_action_duration_seconds=int(
                raw.get("max_action_duration_seconds", defaults.max_action_duration_seconds)
            ),
            loaded_from_defaults=False,
            source_path=str(path),
        )

    def _with_autodetected_gateways(self) -> ResponsePolicyConfig:
        """Add this host's own address and its likely gateway to the denylist.

        Self-protection: the platform must never block the machine it runs on.
        The gateway is inferred as the .1 of the host's /24 — a heuristic, and
        deliberately additive, so a wrong guess protects one extra address
        rather than exposing anything.
        """
        discovered: list[str] = []
        try:
            # A UDP connect() only sets the socket's peer; no packet is sent.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.2)
                sock.connect(("8.8.8.8", 80))
                local_ip = sock.getsockname()[0]
            discovered.append(f"{local_ip}/32")
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            discovered.append(f"{next(network.hosts())}/32")
        except Exception as exc:
            logger.warning(
                "response_policy_gateway_autodetect_failed",
                extra={"error": str(exc)},
            )
            return self

        logger.info(
            "response_policy_gateways_autodetected",
            extra={"protected": discovered},
        )
        return replace(
            self,
            protected_targets=ProtectedTargets(
                cidrs=self.protected_targets.cidrs + tuple(discovered),
                hosts=self.protected_targets.hosts,
            ),
        )
