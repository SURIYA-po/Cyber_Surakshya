"""ResponseAgent read model, analyst approvals, and containment rollback.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from api.projections import active_containments, load_response_records, rehydrate_response
from api.runtime import ensure_runtime, platform
from cyber_surakshya.platform.schemas.response_result import ResponseStatus

router = APIRouter(tags=["response"])


@router.get("/response/actions")
def get_response_actions(status: str | None = None):
    """List response actions, optionally filtered by ResponseStatus."""
    records = load_response_records()
    if status:
        wanted = status.upper()
        records = [r for r in records if r.get("status") == wanted]
    return JSONResponse(content=records)


@router.get("/response/pending-approvals")
def get_pending_approvals():
    """HITL queue: actions the guard or policy deferred to an analyst."""
    records = load_response_records()
    return JSONResponse(
        content=[
            r for r in records
            if r.get("status") == ResponseStatus.AWAITING_APPROVAL.value
        ]
    )


@router.get("/response/actions/{response_id}")
def get_response_action(response_id: str):
    for record in load_response_records():
        if str(record.get("response_id")) == response_id:
            return JSONResponse(content=record)
    raise HTTPException(status_code=404, detail="Response action not found")


@router.post("/response/actions/{decision_id}/approve")
def approve_response_action(decision_id: str, approved_by: str = "analyst", reason: str | None = None):
    """Record analyst approval.

    Approval is stored, not executed here: the next graph run — or an
    explicit re-run of the decision — picks it up via the ApprovalStore.
    """
    ensure_runtime()
    if platform.approval_store is None:
        raise HTTPException(status_code=503, detail="Approval store not initialized")
    ruling = platform.approval_store.approve(decision_id, approved_by=approved_by, reason=reason)
    return JSONResponse(content={
        "decision_id": ruling.decision_id,
        "approved":    ruling.approved,
        "approved_by": ruling.approved_by,
        "reason":      ruling.reason,
    })


@router.post("/response/actions/{decision_id}/reject")
def reject_response_action(decision_id: str, approved_by: str = "analyst", reason: str | None = None):
    """Record analyst rejection. Terminal — the action will never execute."""
    ensure_runtime()
    if platform.approval_store is None:
        raise HTTPException(status_code=503, detail="Approval store not initialized")
    ruling = platform.approval_store.reject(decision_id, approved_by=approved_by, reason=reason)
    return JSONResponse(content={
        "decision_id": ruling.decision_id,
        "approved":    ruling.approved,
        "approved_by": ruling.approved_by,
        "reason":      ruling.reason,
    })


@router.get("/response/policy")
def get_response_policy():
    """Expose the active authorisation policy for operator inspection."""
    ensure_runtime()
    if platform.response_policy is None:
        raise HTTPException(status_code=503, detail="Response policy not initialized")
    return JSONResponse(content={
        "source":              platform.response_policy.source_path or "built_in_defaults",
        "loaded_from_defaults": platform.response_policy.loaded_from_defaults,
        "dry_run":             platform.response_policy.dry_run,
        "engine_trust":        {k: v.value for k, v in platform.response_policy.engine_trust.items()},
        "destructive_actions": sorted(a.value for a in platform.response_policy.destructive_actions),
        "downgrade_action":    platform.response_policy.downgrade_action.value,
        "protected_cidrs":     list(platform.response_policy.protected_targets.cidrs),
        "blast_radius": {
            "max_destructive_per_correlation":
                platform.response_policy.blast_radius.max_destructive_per_correlation,
            "max_destructive_per_target_window_seconds":
                platform.response_policy.blast_radius.max_destructive_per_target_window_seconds,
            "global_destructive_per_minute":
                platform.response_policy.blast_radius.global_destructive_per_minute,
        },
    })


@router.get("/blocked-ips")
def get_blocked_ips():
    """Active containments, projected from real ResponseResult records."""
    return JSONResponse(content=active_containments())


@router.delete("/blocked-ips/{ip_id}")
def delete_blocked_ip(ip_id: str):
    """Revert a containment through the executor that applied it.

    This is a real rollback travelling the same audited path as the original
    action, not a list mutation in the web layer.
    """
    ensure_runtime()

    response_record = next(
        (r for r in load_response_records() if str(r.get("response_id")) == ip_id),
        None,
    )
    if response_record is None:
        # No ResponseResult means nothing was ever executed for this ID, so
        # there is nothing to revert. Say so rather than reporting a successful
        # deletion of a list entry the platform no longer keeps.
        raise HTTPException(
            status_code=404,
            detail=f"No response record {ip_id}; nothing to revert.",
        )

    if platform.response_agent is None:
        raise HTTPException(status_code=503, detail="Response agent not initialized")

    try:
        result = platform.response_agent.revert(rehydrate_response(response_record))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Revert failed: {exc}")

    return JSONResponse(content={
        "status":               "reverted",
        "reverted":             True,
        "response_id":          result.response_id,
        "reverted_response_id": result.reverts_response_id,
    })
