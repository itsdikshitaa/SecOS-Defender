from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog, ResponseAction
from app.schemas import ActionResult, ResponseActionCreate


def create_action(db: Session, payload: ResponseActionCreate) -> ResponseAction:
    action = ResponseAction(
        host_id=payload.host_id,
        type=payload.type,
        parameters=payload.parameters,
        approval_mode=payload.approval_mode,
        ttl_seconds=payload.ttl,
        state="approved" if payload.approval_mode == "automatic" else "pending_approval",
        requested_by=payload.requested_by,
    )
    db.add(action)
    db.flush()
    db.add(
        AuditLog(
            entity_type="response_action",
            entity_id=action.id,
            action="created",
            actor=payload.requested_by,
            details={"type": payload.type, "host_id": payload.host_id},
        )
    )
    db.commit()
    db.refresh(action)
    return action


def approve_action(db: Session, action_id: str, approved_by: str) -> ResponseAction | None:
    action = db.get(ResponseAction, action_id)
    if not action:
        return None
    action.state = "approved"
    action.approved_by = approved_by
    action.approved_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            entity_type="response_action",
            entity_id=action.id,
            action="approved",
            actor=approved_by,
            details={"host_id": action.host_id},
        )
    )
    db.commit()
    db.refresh(action)
    return action


def poll_actions(db: Session, host_id: str) -> list[ResponseAction]:
    return db.scalars(
        select(ResponseAction).where(
            ResponseAction.host_id == host_id,
            ResponseAction.state == "approved",
        )
    ).all()


def mark_action_result(db: Session, action_id: str, payload: ActionResult) -> ResponseAction | None:
    action = db.get(ResponseAction, action_id)
    if not action:
        return None
    action.state = payload.state
    action.result = payload.result
    db.add(
        AuditLog(
            entity_type="response_action",
            entity_id=action.id,
            action="result",
            actor="agent",
            details={"state": payload.state, "result": payload.result},
        )
    )
    db.commit()
    db.refresh(action)
    return action
