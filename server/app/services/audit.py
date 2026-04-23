from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models import AuditLog


def log_action(
    db: Session,
    entity_type: str,
    entity_id: str,
    action: str,
    actor: str,
    details: dict | None = None,
    occurred_at: datetime | None = None,
) -> AuditLog:
    """
    Log an audit entry for compliance and investigation.
    
    Args:
        db: Database session
        entity_type: Type of entity affected (e.g., 'alert', 'action', 'rule', 'user')
        entity_id: ID of the entity
        action: Action performed (e.g., 'created', 'approved', 'resolved', 'login')
        actor: Username or service that performed the action
        details: Additional context (optional)
        occurred_at: Timestamp of the action (defaults to now)
    
    Returns:
        Created AuditLog entry
    """
    if occurred_at is None:
        occurred_at = datetime.now(timezone.utc)
    
    entry = AuditLog(
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        actor=actor,
        details=details or {},
        occurred_at=occurred_at,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def get_audit_log(
    db: Session,
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLog]:
    """
    Retrieve audit log entries with optional filtering.
    
    Returns:
        List of AuditLog entries, ordered by most recent first
    """
    query = select(AuditLog)
    
    if entity_type:
        query = query.where(AuditLog.entity_type == entity_type)
    if entity_id:
        query = query.where(AuditLog.entity_id == entity_id)
    if action:
        query = query.where(AuditLog.action == action)
    if actor:
        query = query.where(AuditLog.actor == actor)
    
    query = query.order_by(AuditLog.occurred_at.desc()).offset(offset).limit(limit)
    return db.scalars(query).all()


def get_user_actions(db: Session, actor: str, limit: int = 100) -> list[AuditLog]:
    """Get all actions performed by a specific user."""
    return get_audit_log(db, actor=actor, limit=limit)


def get_entity_history(db: Session, entity_type: str, entity_id: str) -> list[AuditLog]:
    """Get full audit history for a specific entity (alert, action, etc.)."""
    return get_audit_log(db, entity_type=entity_type, entity_id=entity_id, limit=1000)
