from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models import Alert, Finding, Vulnerability


def export_alerts_csv(db: Session, filters: dict[str, Any] | None = None) -> str:
    """
    Export alerts to CSV format.
    
    Returns:
        CSV string (can be saved to file or sent as response)
    """
    query = select(Alert)
    
    if filters:
        if filters.get("host_id"):
            query = query.where(Alert.host_id == filters["host_id"])
        if filters.get("severity"):
            query = query.where(Alert.severity == filters["severity"])
        if filters.get("rule_id"):
            query = query.where(Alert.rule_id == filters["rule_id"])
        if filters.get("status"):
            query = query.where(Alert.status == filters["status"])
    
    alerts = db.scalars(query.order_by(Alert.created_at.desc())).all()
    
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "Alert ID",
            "Host ID",
            "Event ID",
            "Rule ID",
            "Title",
            "Summary",
            "Severity",
            "Status",
            "Created At",
        ],
    )
    
    writer.writeheader()
    for alert in alerts:
        writer.writerow({
            "Alert ID": alert.id,
            "Host ID": alert.host_id,
            "Event ID": alert.event_id,
            "Rule ID": alert.rule_id,
            "Title": alert.title,
            "Summary": alert.summary,
            "Severity": alert.severity,
            "Status": alert.status,
            "Created At": alert.created_at.isoformat(),
        })
    
    return output.getvalue()


def export_alerts_json(db: Session, filters: dict[str, Any] | None = None) -> str:
    """
    Export alerts to JSON format.
    
    Returns:
        JSON string
    """
    query = select(Alert)
    
    if filters:
        if filters.get("host_id"):
            query = query.where(Alert.host_id == filters["host_id"])
        if filters.get("severity"):
            query = query.where(Alert.severity == filters["severity"])
        if filters.get("rule_id"):
            query = query.where(Alert.rule_id == filters["rule_id"])
        if filters.get("status"):
            query = query.where(Alert.status == filters["status"])
    
    alerts = db.scalars(query.order_by(Alert.created_at.desc())).all()
    
    data = [
        {
            "id": alert.id,
            "host_id": alert.host_id,
            "event_id": alert.event_id,
            "rule_id": alert.rule_id,
            "title": alert.title,
            "summary": alert.summary,
            "severity": alert.severity,
            "status": alert.status,
            "evidence": alert.evidence,
            "recommended_actions": alert.recommended_actions,
            "created_at": alert.created_at.isoformat(),
        }
        for alert in alerts
    ]
    
    return json.dumps(data, indent=2, default=str)


def export_findings_csv(db: Session, filters: dict[str, Any] | None = None) -> str:
    """Export findings to CSV format."""
    query = select(Finding)
    
    if filters:
        if filters.get("host_id"):
            query = query.where(Finding.host_id == filters["host_id"])
        if filters.get("severity"):
            query = query.where(Finding.severity == filters["severity"])
        if filters.get("status"):
            query = query.where(Finding.status == filters["status"])
        if filters.get("category"):
            query = query.where(Finding.category == filters["category"])
    
    findings = db.scalars(query.order_by(Finding.created_at.desc())).all()
    
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "Finding ID",
            "Host ID",
            "Category",
            "Title",
            "Description",
            "Severity",
            "Status",
            "First Seen",
            "Last Seen",
        ],
    )
    
    writer.writeheader()
    for finding in findings:
        writer.writerow({
            "Finding ID": finding.id,
            "Host ID": finding.host_id,
            "Category": finding.category,
            "Title": finding.title,
            "Description": finding.description[:100],
            "Severity": finding.severity,
            "Status": finding.status,
            "First Seen": finding.first_seen.isoformat(),
            "Last Seen": finding.last_seen.isoformat(),
        })
    
    return output.getvalue()


def export_findings_json(db: Session, filters: dict[str, Any] | None = None) -> str:
    """Export findings to JSON format."""
    query = select(Finding)
    
    if filters:
        if filters.get("host_id"):
            query = query.where(Finding.host_id == filters["host_id"])
        if filters.get("severity"):
            query = query.where(Finding.severity == filters["severity"])
        if filters.get("status"):
            query = query.where(Finding.status == filters["status"])
        if filters.get("category"):
            query = query.where(Finding.category == filters["category"])
    
    findings = db.scalars(query.order_by(Finding.created_at.desc())).all()
    
    data = [
        {
            "id": finding.id,
            "host_id": finding.host_id,
            "category": finding.category,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "status": finding.status,
            "evidence": finding.evidence,
            "recommended_actions": finding.recommended_actions,
            "first_seen": finding.first_seen.isoformat(),
            "last_seen": finding.last_seen.isoformat(),
        }
        for finding in findings
    ]
    
    return json.dumps(data, indent=2, default=str)


def export_vulnerabilities_csv(db: Session, filters: dict[str, Any] | None = None) -> str:
    """Export vulnerabilities to CSV format."""
    query = select(Vulnerability)
    
    if filters:
        if filters.get("host_id"):
            query = query.where(Vulnerability.host_id == filters["host_id"])
        if filters.get("severity"):
            query = query.where(Vulnerability.severity == filters["severity"])
        if filters.get("status"):
            query = query.where(Vulnerability.status == filters["status"])
    
    vulns = db.scalars(query.order_by(Vulnerability.updated_at.desc())).all()
    
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "Host ID",
            "CVE ID",
            "Package Name",
            "Installed Version",
            "Fixed Version",
            "Severity",
            "Status",
            "First Seen",
        ],
    )
    
    writer.writeheader()
    for vuln in vulns:
        writer.writerow({
            "Host ID": vuln.host_id,
            "CVE ID": vuln.cve_id,
            "Package Name": vuln.package_name,
            "Installed Version": vuln.installed_version,
            "Fixed Version": vuln.fixed_version or "N/A",
            "Severity": vuln.severity,
            "Status": vuln.status,
            "First Seen": vuln.first_seen.isoformat(),
        })
    
    return output.getvalue()


def export_vulnerabilities_json(db: Session, filters: dict[str, Any] | None = None) -> str:
    """Export vulnerabilities to JSON format."""
    query = select(Vulnerability)
    
    if filters:
        if filters.get("host_id"):
            query = query.where(Vulnerability.host_id == filters["host_id"])
        if filters.get("severity"):
            query = query.where(Vulnerability.severity == filters["severity"])
        if filters.get("status"):
            query = query.where(Vulnerability.status == filters["status"])
    
    vulns = db.scalars(query.order_by(Vulnerability.updated_at.desc())).all()
    
    data = [
        {
            "host_id": vuln.host_id,
            "cve_id": vuln.cve_id,
            "package_name": vuln.package_name,
            "installed_version": vuln.installed_version,
            "fixed_version": vuln.fixed_version,
            "severity": vuln.severity,
            "status": vuln.status,
            "description": vuln.description,
            "references": vuln.references,
            "first_seen": vuln.first_seen.isoformat(),
        }
        for vuln in vulns
    ]
    
    return json.dumps(data, indent=2, default=str)


def create_incident_report(
    db: Session,
    host_id: str | None = None,
    severity_filter: str | None = None,
) -> str:
    """
    Create a comprehensive incident report in JSON.
    
    Returns:
        JSON string with alerts, findings, and vulnerabilities summary
    """
    alert_query = select(Alert)
    finding_query = select(Finding)
    vuln_query = select(Vulnerability)
    
    if host_id:
        alert_query = alert_query.where(Alert.host_id == host_id)
        finding_query = finding_query.where(Finding.host_id == host_id)
        vuln_query = vuln_query.where(Vulnerability.host_id == host_id)
    
    if severity_filter:
        alert_query = alert_query.where(Alert.severity == severity_filter)
        finding_query = finding_query.where(Finding.severity == severity_filter)
        vuln_query = vuln_query.where(Vulnerability.severity == severity_filter)
    
    alerts = db.scalars(alert_query.order_by(Alert.created_at.desc())).all()
    findings = db.scalars(finding_query.order_by(Finding.created_at.desc())).all()
    vulns = db.scalars(vuln_query.order_by(Vulnerability.updated_at.desc())).all()
    
    report = {
        "generated_at": datetime.utcnow().isoformat(),
        "host_id": host_id,
        "severity_filter": severity_filter,
        "summary": {
            "total_alerts": len(alerts),
            "total_findings": len(findings),
            "total_vulnerabilities": len(vulns),
            "alerts_by_severity": {
                "critical": len([a for a in alerts if a.severity == "critical"]),
                "high": len([a for a in alerts if a.severity == "high"]),
                "medium": len([a for a in alerts if a.severity == "medium"]),
                "low": len([a for a in alerts if a.severity == "low"]),
            },
        },
        "alerts": [
            {
                "id": a.id,
                "host_id": a.host_id,
                "rule_id": a.rule_id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts[:50]
        ],
        "findings": [
            {
                "id": f.id,
                "host_id": f.host_id,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "last_seen": f.last_seen.isoformat(),
            }
            for f in findings[:50]
        ],
        "vulnerabilities": [
            {
                "cve_id": v.cve_id,
                "package_name": v.package_name,
                "severity": v.severity,
                "installed_version": v.installed_version,
                "fixed_version": v.fixed_version,
            }
            for v in vulns[:50]
        ],
    }
    
    return json.dumps(report, indent=2, default=str)
