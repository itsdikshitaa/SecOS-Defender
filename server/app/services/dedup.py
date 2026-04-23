from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models import Alert, AlertSuppression


def check_should_suppress_alert(db: Session, alert: Alert) -> bool:
    """
    Check if an alert should be suppressed based on active suppression rules.
    
    Returns:
        True if alert should be suppressed, False otherwise
    """
    if not alert.rule_id:
        return False
    
    query = select(AlertSuppression).where(
        AlertSuppression.rule_id == alert.rule_id,
        AlertSuppression.is_active == True,
    )
    
    if alert.host_id:
        query = query.where(
            (AlertSuppression.host_id == alert.host_id) | (AlertSuppression.host_id.is_(None))
        )
    
    suppression = db.execute(query).scalar_one_or_none()
    
    if not suppression:
        return False
    
    if suppression.expires_at and suppression.expires_at < datetime.now(timezone.utc):
        suppression.is_active = False
        db.commit()
        return False
    
    return True


def create_suppression(
    db: Session,
    rule_id: str,
    reason: str,
    created_by: str,
    host_id: str | None = None,
    expires_in_days: int | None = None,
    metadata: dict | None = None,
) -> AlertSuppression:
    """
    Create a new alert suppression rule.
    
    Args:
        db: Database session
        rule_id: Rule to suppress
        reason: Human-readable reason for suppression
        created_by: User who created the suppression
        host_id: Optional - suppress only for specific host
        expires_in_days: Optional - auto-expire suppression after N days
        metadata: Optional - additional context
    
    Returns:
        Created AlertSuppression
    """
    expires_at = None
    if expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
    
    suppression = AlertSuppression(
        rule_id=rule_id,
        host_id=host_id,
        is_active=True,
        reason=reason,
        expires_at=expires_at,
        created_by=created_by,
        metadata_json=metadata or {},
    )
    db.add(suppression)
    db.commit()
    db.refresh(suppression)
    return suppression


def disable_suppression(db: Session, suppression_id: str) -> AlertSuppression | None:
    """Disable an active suppression rule."""
    suppression = db.get(AlertSuppression, suppression_id)
    if suppression:
        suppression.is_active = False
        db.commit()
        db.refresh(suppression)
    return suppression


def get_active_suppressions(
    db: Session,
    rule_id: str | None = None,
    host_id: str | None = None,
) -> list[AlertSuppression]:
    """Get all active suppression rules."""
    query = select(AlertSuppression).where(AlertSuppression.is_active == True)
    
    now = datetime.now(timezone.utc)
    
    if rule_id:
        query = query.where(AlertSuppression.rule_id == rule_id)
    if host_id:
        query = query.where(
            (AlertSuppression.host_id == host_id) | (AlertSuppression.host_id.is_(None))
        )
    
    suppressions = db.scalars(query).all()
    
    expired = []
    for s in suppressions:
        if s.expires_at and s.expires_at < now:
            s.is_active = False
            expired.append(s)
    
    if expired:
        db.commit()
        return [s for s in suppressions if s not in expired]
    
    return suppressions


def check_is_duplicate_alert(
    db: Session,
    rule_id: str,
    host_id: str,
    time_window_seconds: int = 3600,
) -> bool:
    """
    Check if a similar alert was created recently (within time window).
    This helps deduplicate high-frequency alerts.
    
    Args:
        db: Database session
        rule_id: Rule ID to check
        host_id: Host ID to check
        time_window_seconds: Look back window (default 1 hour)
    
    Returns:
        True if similar alert found within time window
    """
    cutoff_time = datetime.now(timezone.utc) - timedelta(seconds=time_window_seconds)
    
    recent = db.execute(
        select(Alert).where(
            Alert.rule_id == rule_id,
            Alert.host_id == host_id,
            Alert.created_at > cutoff_time,
            Alert.status != "resolved",
        )
    ).scalar_one_or_none()
    
    return recent is not None


def mark_alert_as_false_positive(
    db: Session,
    alert_id: str,
    marked_by: str,
    reason: str = "",
) -> Alert | None:
    """
    Mark an alert as false positive and optionally create suppression rule.
    
    Returns:
        Updated Alert
    """
    alert = db.get(Alert, alert_id)
    if not alert:
        return None
    
    alert.status = "false_positive"
    db.commit()
    db.refresh(alert)
    
    from app.services.audit import log_action
    
    log_action(
        db,
        entity_type="alert",
        entity_id=alert_id,
        action="marked_false_positive",
        actor=marked_by,
        details={"reason": reason, "rule_id": alert.rule_id},
    )
    
    return alert
