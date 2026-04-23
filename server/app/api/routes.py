from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, Response
from fastapi.responses import StreamingResponse

from app.db import get_db
from app.models import AgentHealth, Host, ResponseAction, RulePack, SoftwareInventory, Vulnerability, Alert, Finding
from app.schemas import ActionApproval, ActionResult, DashboardSnapshot, EventBatch, Heartbeat, InventoryReport, ResponseActionCreate
from app.services.actions import approve_action, create_action, mark_action_result, poll_actions
from app.services.broadcaster import hub
from app.services.pipeline import ensure_host, get_overview_metrics, get_recent_alerts, get_recent_findings, ingest_events
from app.services.export import (
    export_alerts_csv,
    export_alerts_json,
    export_findings_csv,
    export_findings_json,
    export_vulnerabilities_csv,
    export_vulnerabilities_json,
    create_incident_report,
)


router = APIRouter()


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@router.post("/ingest/events")
async def ingest_events_route(payload: EventBatch, request: Request, db: Session = Depends(get_db)):
    result = await ingest_events(db, payload, request.app.state.rule_engine)
    return {"message": "events ingested", **result}


@router.post("/ingest/inventory")
async def ingest_inventory(payload: InventoryReport, request: Request, db: Session = Depends(get_db)):
    ensure_host(db, payload.host_id, payload.platform, payload.hostname)
    packages = [
        SoftwareInventory(
            host_id=payload.host_id,
            package_name=package.name,
            version=package.version,
            architecture=package.architecture,
            source=package.source,
            installed_at=package.installed_at,
            metadata_json=package.metadata,
        )
        for package in payload.packages
    ]
    request.app.state.vulnerability_service.replace_inventory(db, payload.host_id, packages)
    matches = request.app.state.vulnerability_service.correlate_inventory(db, payload.host_id)
    await hub.broadcast(
        "vulnerabilities.updated",
        {
            "host_id": payload.host_id,
            "count": len(matches),
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "package_name": vuln.package_name,
                    "severity": vuln.severity,
                    "status": vuln.status,
                }
                for vuln in matches
            ],
        },
    )
    return {"message": "inventory ingested", "vulnerabilities": len(matches)}


@router.post("/agents/heartbeat")
async def heartbeat(payload: Heartbeat, db: Session = Depends(get_db)):
    host = ensure_host(db, payload.host_id, payload.platform, payload.hostname)
    host.ip_address = payload.ip_address
    record = db.scalar(select(AgentHealth).where(AgentHealth.host_id == payload.host_id))
    if not record:
        db.add(
            AgentHealth(
                host_id=payload.host_id,
                status=payload.status,
                agent_version=payload.agent_version,
                queue_depth=payload.queue_depth,
                metadata_json=payload.metadata,
            )
        )
    else:
        record.status = payload.status
        record.agent_version = payload.agent_version
        record.queue_depth = payload.queue_depth
        record.last_seen = host.last_seen
        record.metadata_json = payload.metadata
    db.commit()
    await hub.broadcast(
        "hosts.updated",
        {"host_id": payload.host_id, "status": payload.status, "queue_depth": payload.queue_depth},
    )
    return {"message": "heartbeat accepted"}


@router.get("/actions/poll")
def poll_actions_route(host_id: str = Query(...), db: Session = Depends(get_db)):
    return [
        {
            "action_id": action.id,
            "type": action.type,
            "host_id": action.host_id,
            "parameters": action.parameters,
            "approval_mode": action.approval_mode,
            "ttl": action.ttl_seconds,
            "state": action.state,
        }
        for action in poll_actions(db, host_id)
    ]


@router.post("/actions")
async def create_action_route(payload: ResponseActionCreate, db: Session = Depends(get_db)):
    action = create_action(db, payload)
    await hub.broadcast(
        "actions.updated",
        {"action_id": action.id, "host_id": action.host_id, "state": action.state, "type": action.type},
    )
    return {"action_id": action.id, "state": action.state}


@router.post("/actions/{action_id}/approve")
async def approve_action_route(action_id: str, payload: ActionApproval, db: Session = Depends(get_db)):
    action = approve_action(db, action_id, payload.approved_by)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    await hub.broadcast(
        "actions.updated",
        {"action_id": action.id, "host_id": action.host_id, "state": action.state},
    )
    return {"action_id": action.id, "state": action.state}


@router.post("/actions/{action_id}/result")
async def action_result_route(action_id: str, payload: ActionResult, db: Session = Depends(get_db)):
    action = mark_action_result(db, action_id, payload)
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")
    await hub.broadcast(
        "actions.updated",
        {"action_id": action.id, "host_id": action.host_id, "state": action.state},
    )
    return {"action_id": action.id, "state": action.state}


@router.get("/overview", response_model=DashboardSnapshot)
def overview(db: Session = Depends(get_db)):
    vulnerabilities = db.scalars(select(Vulnerability).order_by(Vulnerability.updated_at.desc()).limit(12)).all()
    hosts = db.scalars(select(Host).order_by(Host.last_seen.desc()).limit(20)).all()
    return DashboardSnapshot(
        metrics=get_overview_metrics(db),
        alerts=get_recent_alerts(db, limit=12),
        findings=get_recent_findings(db, limit=12),
        vulnerabilities=[
            {
                "id": vuln.id,
                "host_id": vuln.host_id,
                "cve_id": vuln.cve_id,
                "package_name": vuln.package_name,
                "installed_version": vuln.installed_version,
                "fixed_version": vuln.fixed_version,
                "severity": vuln.severity,
                "status": vuln.status,
            }
            for vuln in vulnerabilities
        ],
        hosts=[
            {
                "id": host.id,
                "hostname": host.hostname,
                "platform": host.platform,
                "ip_address": host.ip_address,
                "last_seen": host.last_seen.isoformat(),
            }
            for host in hosts
        ],
    )


@router.get("/rules")
def rules(db: Session = Depends(get_db)):
    rows = db.scalars(select(RulePack).order_by(RulePack.pack_id)).all()
    return [
        {
            "pack_id": row.pack_id,
            "title": row.title,
            "version": row.version,
            "status": row.status,
            "enabled": row.enabled,
        }
        for row in rows
    ]


@router.get("/hosts")
def hosts(db: Session = Depends(get_db)):
    rows = db.scalars(select(Host).order_by(Host.last_seen.desc())).all()
    return [
        {
            "id": row.id,
            "hostname": row.hostname,
            "platform": row.platform,
            "ip_address": row.ip_address,
            "last_seen": row.last_seen.isoformat(),
        }
        for row in rows
    ]


@router.get("/alerts")
def alerts(
    limit: int = 50,
    offset: int = 0,
    host_id: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    status: str | None = None,
    search: str | None = None,
    db: Session = Depends(get_db)
):
    """
    Get alerts with advanced filtering.
    
    Query parameters:
    - limit: Number of results (default 50, max 500)
    - offset: Pagination offset (default 0)
    - host_id: Filter by host ID
    - severity: Filter by severity (critical, high, medium, low)
    - rule_id: Filter by rule ID
    - status: Filter by alert status (open, acknowledged, resolved)
    - search: Full-text search in title/summary
    """
    limit = min(limit, 500)
    
    query = select(Alert)
    
    if host_id:
        query = query.where(Alert.host_id == host_id)
    if severity:
        query = query.where(Alert.severity == severity)
    if rule_id:
        query = query.where(Alert.rule_id == rule_id)
    if status:
        query = query.where(Alert.status == status)
    if search:
        query = query.where(
            (Alert.title.ilike(f"%{search}%")) | (Alert.summary.ilike(f"%{search}%"))
        )
    
    query = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
    rows = db.scalars(query).all()
    
    return [
        {
            "id": row.id,
            "host_id": row.host_id,
            "event_id": row.event_id,
            "rule_id": row.rule_id,
            "title": row.title,
            "summary": row.summary,
            "severity": row.severity,
            "status": row.status,
            "created_at": row.created_at.isoformat(),
        }
        for row in rows
    ]


@router.get("/findings")
def findings(
    limit: int = 50,
    offset: int = 0,
    host_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    search: str | None = None,
    db: Session = Depends(get_db)
):
    """
    Get findings with advanced filtering.
    
    Query parameters:
    - limit: Number of results (default 50, max 500)
    - offset: Pagination offset (default 0)
    - host_id: Filter by host ID
    - severity: Filter by severity (critical, high, medium, low)
    - status: Filter by status (open, acknowledged, resolved)
    - category: Filter by finding category
    - search: Full-text search in title/description
    """
    limit = min(limit, 500)
    
    query = select(Finding)
    
    if host_id:
        query = query.where(Finding.host_id == host_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)
    if search:
        query = query.where(
            (Finding.title.ilike(f"%{search}%")) | (Finding.description.ilike(f"%{search}%"))
        )
    
    query = query.order_by(Finding.created_at.desc()).offset(offset).limit(limit)
    rows = db.scalars(query).all()
    
    return [
        {
            "id": row.id,
            "host_id": row.host_id,
            "category": row.category,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "status": row.status,
            "first_seen": row.first_seen.isoformat(),
            "last_seen": row.last_seen.isoformat(),
        }
        for row in rows
    ]


@router.get("/vulnerabilities")
def vulnerabilities(
    limit: int = 50,
    offset: int = 0,
    host_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    cve_id: str | None = None,
    package_name: str | None = None,
    db: Session = Depends(get_db)
):
    """
    Get vulnerabilities with advanced filtering.
    
    Query parameters:
    - limit: Number of results (default 50, max 500)
    - offset: Pagination offset (default 0)
    - host_id: Filter by host ID
    - severity: Filter by severity (critical, high, medium, low)
    - status: Filter by status (open, resolved)
    - cve_id: Filter by CVE ID
    - package_name: Filter by package name
    """
    limit = min(limit, 500)
    
    query = select(Vulnerability)
    
    if host_id:
        query = query.where(Vulnerability.host_id == host_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    if cve_id:
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
    if package_name:
        query = query.where(Vulnerability.package_name.ilike(f"%{package_name}%"))
    
    query = query.order_by(Vulnerability.updated_at.desc()).offset(offset).limit(limit)
    rows = db.scalars(query).all()
    
    return [
        {
            "id": row.id,
            "host_id": row.host_id,
            "cve_id": row.cve_id,
            "package_name": row.package_name,
            "installed_version": row.installed_version,
            "fixed_version": row.fixed_version,
            "severity": row.severity,
            "status": row.status,
            "description": row.description,
            "references": row.references,
        }
        for row in rows
    ]


@router.get("/actions")
def response_actions(db: Session = Depends(get_db)):
    rows = db.scalars(select(ResponseAction).order_by(ResponseAction.created_at.desc())).all()
    return [
        {
            "id": row.id,
            "host_id": row.host_id,
            "type": row.type,
            "state": row.state,
            "approval_mode": row.approval_mode,
            "ttl": row.ttl_seconds,
            "requested_by": row.requested_by,
        }
        for row in rows
    ]


@router.websocket("/ws/stream")
async def event_stream(websocket: WebSocket):
    await hub.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(websocket)


@router.get("/audit-log")
def get_audit_log_endpoint(
    limit: int = 100,
    offset: int = 0,
    entity_type: str | None = None,
    entity_id: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Get audit log entries for compliance and investigation.
    
    Query parameters:
    - limit: Number of results (default 100, max 500)
    - offset: Pagination offset (default 0)
    - entity_type: Filter by entity type (response_action, user, rule, etc.)
    - entity_id: Filter by specific entity ID
    - action: Filter by action (created, approved, resolved, login, etc.)
    - actor: Filter by user/service that performed the action
    """
    from app.services.audit import get_audit_log
    
    limit = min(limit, 500)
    entries = get_audit_log(
        db,
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        actor=actor,
        limit=limit,
        offset=offset,
    )
    
    return [
        {
            "id": entry.id,
            "entity_type": entry.entity_type,
            "entity_id": entry.entity_id,
            "action": entry.action,
            "actor": entry.actor,
            "occurred_at": entry.occurred_at.isoformat(),
            "details": entry.details,
        }
        for entry in entries
    ]


@router.get("/export/alerts/csv")
def export_alerts_csv_endpoint(
    host_id: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    """Export alerts as CSV file."""
    filters = {
        "host_id": host_id,
        "severity": severity,
        "rule_id": rule_id,
        "status": status,
    }
    csv_content = export_alerts_csv(db, {k: v for k, v in filters.items() if v})
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts.csv"},
    )


@router.get("/export/alerts/json")
def export_alerts_json_endpoint(
    host_id: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    """Export alerts as JSON file."""
    filters = {
        "host_id": host_id,
        "severity": severity,
        "rule_id": rule_id,
        "status": status,
    }
    json_content = export_alerts_json(db, {k: v for k, v in filters.items() if v})
    
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=alerts.json"},
    )


@router.get("/export/findings/csv")
def export_findings_csv_endpoint(
    host_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    db: Session = Depends(get_db),
):
    """Export findings as CSV file."""
    filters = {
        "host_id": host_id,
        "severity": severity,
        "status": status,
        "category": category,
    }
    csv_content = export_findings_csv(db, {k: v for k, v in filters.items() if v})
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings.csv"},
    )


@router.get("/export/findings/json")
def export_findings_json_endpoint(
    host_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    db: Session = Depends(get_db),
):
    """Export findings as JSON file."""
    filters = {
        "host_id": host_id,
        "severity": severity,
        "status": status,
        "category": category,
    }
    json_content = export_findings_json(db, {k: v for k, v in filters.items() if v})
    
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=findings.json"},
    )


@router.get("/export/vulnerabilities/csv")
def export_vulnerabilities_csv_endpoint(
    host_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    """Export vulnerabilities as CSV file."""
    filters = {
        "host_id": host_id,
        "severity": severity,
        "status": status,
    }
    csv_content = export_vulnerabilities_csv(db, {k: v for k, v in filters.items() if v})
    
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
    )


@router.get("/export/vulnerabilities/json")
def export_vulnerabilities_json_endpoint(
    host_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    """Export vulnerabilities as JSON file."""
    filters = {
        "host_id": host_id,
        "severity": severity,
        "status": status,
    }
    json_content = export_vulnerabilities_json(db, {k: v for k, v in filters.items() if v})
    
    return Response(
        content=json_content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.json"},
    )


@router.get("/export/incident-report")
def export_incident_report_endpoint(
    host_id: str | None = None,
    severity: str | None = None,
    db: Session = Depends(get_db),
):
    """
    Generate comprehensive incident report (JSON).
    Includes alerts, findings, vulnerabilities summary and details.
    """
    report_content = create_incident_report(db, host_id=host_id, severity_filter=severity)
    
    return Response(
        content=report_content,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=incident_report.json"},
    )
