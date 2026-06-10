from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Alert, Event, Finding, Host
from app.schemas import EventBatch, NormalizedEvent, OverviewMetric
from app.services.broadcaster import hub
from app.services.rules import RuleEngine, RuleMatch


def ensure_host(db: Session, host_id: str, platform: str, hostname: str | None = None) -> Host:
    host = db.get(Host, host_id)
    if not host:
        host = Host(id=host_id, platform=platform, hostname=hostname)
        db.add(host)
    else:
        host.platform = platform
        if hostname:
            host.hostname = hostname
    host.last_seen = datetime.now(timezone.utc)
    db.flush()
    return host


def _event_to_record(event: NormalizedEvent, batch_id: str | None) -> Event:
    return Event(
        event_id=event.event_id,
        batch_id=batch_id,
        host_id=event.host_id,
        platform=event.platform,
        source=event.source,
        event_type=event.event_type,
        occurred_at=event.occurred_at,
        severity=event.severity.lower(),
        principal=event.principal.model_dump(exclude_none=True),
        process=event.process.model_dump(exclude_none=True),
        network=event.network.model_dump(exclude_none=True),
        file=event.file.model_dump(exclude_none=True),
        registry_data=event.registry.model_dump(exclude_none=True),
        tags=event.tags,
        raw_payload=event.raw_payload,
    )


def _correlation_key(host_id: str, match: RuleMatch) -> str:
    return f"rule:{host_id}:{match.rule_id}"


async def ingest_events(db: Session, payload: EventBatch, rule_engine: RuleEngine) -> dict[str, Any]:
    stored = 0
    alerts_created = 0
    for event in payload.events:
        ensure_host(db, event.host_id, event.platform)
        existing = db.scalar(select(Event).where(Event.event_id == event.event_id))
        if existing:
            continue

        db.add(_event_to_record(event, payload.batch_id))
        db.flush()
        stored += 1

        event_document = {
            **event.model_dump(mode="json"),
            "principal": event.principal.model_dump(exclude_none=True),
            "process": event.process.model_dump(exclude_none=True),
            "network": event.network.model_dump(exclude_none=True),
            "file": event.file.model_dump(exclude_none=True),
            "registry": event.registry.model_dump(exclude_none=True),
        }
        matches = rule_engine.evaluate(event_document)
        for match in matches:
            correlation_key = _correlation_key(event.host_id, match)
            finding = db.scalar(select(Finding).where(Finding.correlation_key == correlation_key))
            if not finding:
                finding = Finding(
                    category="runtime",
                    rule_id=match.rule_id,
                    host_id=event.host_id,
                    status="open",
                    title=match.title,
                    description=match.description,
                    severity=match.severity,
                    correlation_key=correlation_key,
                    evidence=match.evidence,
                    recommended_actions=match.recommended_actions,
                )
                db.add(finding)
                db.flush()
            else:
                finding.status = "open"
                finding.last_seen = datetime.now(timezone.utc)
                finding.evidence = match.evidence
                finding.recommended_actions = match.recommended_actions

            db.add(
                Alert(
                    host_id=event.host_id,
                    event_id=event.event_id,
                    finding_id=finding.id,
                    rule_id=match.rule_id,
                    title=match.title,
                    summary=match.description,
                    severity=match.severity,
                    evidence=match.evidence,
                    recommended_actions=match.recommended_actions,
                )
            )
            alerts_created += 1

        if matches:
            await hub.broadcast(
                "alerts.updated",
                {"host_id": event.host_id, "alerts": get_recent_alerts(db, limit=5), "event_id": event.event_id},
            )

    db.commit()
    return {"stored_events": stored, "alerts_created": alerts_created}


def get_recent_alerts(db: Session, limit: int = 20) -> list[dict[str, Any]]:
    rows = db.scalars(select(Alert).order_by(Alert.created_at.desc()).limit(limit)).all()
    return [
        {
            "id": row.id,
            "host_id": row.host_id,
            "rule_id": row.rule_id,
            "title": row.title,
            "summary": row.summary,
            "severity": row.severity,
            "status": row.status,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


def get_recent_findings(db: Session, limit: int = 20) -> list[dict[str, Any]]:
    rows = db.scalars(select(Finding).order_by(Finding.updated_at.desc()).limit(limit)).all()
    return [
        {
            "id": row.id,
            "host_id": row.host_id,
            "category": row.category,
            "title": row.title,
            "severity": row.severity,
            "status": row.status,
            "updated_at": row.updated_at.isoformat(),
        }
        for row in rows
    ]


def get_overview_metrics(db: Session) -> list[OverviewMetric]:
    open_alerts = db.scalar(select(func.count()).select_from(Alert).where(Alert.status == "open")) or 0
    open_findings = db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "open")) or 0
    hosts = db.scalar(select(func.count()).select_from(Host)) or 0
    high_severity = (
        db.scalar(select(func.count()).select_from(Alert).where(Alert.severity.in_(["high", "critical"]))) or 0
    )
    return [
        OverviewMetric(label="Live Alerts", value=open_alerts, trend="Rules firing now"),
        OverviewMetric(label="Open Findings", value=open_findings, trend="Correlated analyst queue"),
        OverviewMetric(label="Protected Hosts", value=hosts, trend="Reporting within the last cycle"),
        OverviewMetric(label="High/Critical", value=high_severity, trend="Needs immediate triage"),
    ]
