from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect

from app.db import get_db
from app.models import AgentHealth, Host, ResponseAction, RulePack, SoftwareInventory, Vulnerability
from app.schemas import ActionApproval, ActionResult, DashboardSnapshot, EventBatch, Heartbeat, InventoryReport, ResponseActionCreate
from app.services.actions import approve_action, create_action, mark_action_result, poll_actions
from app.services.broadcaster import hub
from app.services.pipeline import ensure_host, get_overview_metrics, get_recent_alerts, get_recent_findings, ingest_events


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
def alerts(limit: int = 30, db: Session = Depends(get_db)):
    return get_recent_alerts(db, limit=limit)


@router.get("/findings")
def findings(limit: int = 30, db: Session = Depends(get_db)):
    return get_recent_findings(db, limit=limit)


@router.get("/vulnerabilities")
def vulnerabilities(limit: int = 30, db: Session = Depends(get_db)):
    rows = db.scalars(select(Vulnerability).order_by(Vulnerability.updated_at.desc()).limit(limit)).all()
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
