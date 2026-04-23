from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class PrincipalContext(BaseModel):
    username: str | None = None
    user_id: str | None = None
    domain: str | None = None


class ProcessContext(BaseModel):
    name: str | None = None
    pid: int | None = None
    parent_pid: int | None = None
    command_line: str | None = None
    path: str | None = None
    sha256: str | None = None


class NetworkContext(BaseModel):
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    direction: str | None = None


class FileContext(BaseModel):
    path: str | None = None
    action: str | None = None
    sha256: str | None = None


class RegistryContext(BaseModel):
    key_path: str | None = None
    value_name: str | None = None
    value_data: str | None = None
    action: str | None = None


class NormalizedEvent(BaseModel):
    event_id: str
    host_id: str
    platform: Literal["linux", "windows", "macos", "network", "generic"] = "generic"
    source: str
    event_type: str
    occurred_at: datetime
    severity: str = "medium"
    principal: PrincipalContext = Field(default_factory=PrincipalContext)
    process: ProcessContext = Field(default_factory=ProcessContext)
    network: NetworkContext = Field(default_factory=NetworkContext)
    file: FileContext = Field(default_factory=FileContext)
    registry: RegistryContext = Field(default_factory=RegistryContext)
    tags: list[str] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class EventBatch(BaseModel):
    batch_id: str | None = None
    events: list[NormalizedEvent]


class InventoryPackage(BaseModel):
    name: str
    version: str
    architecture: str | None = None
    source: str | None = None
    installed_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class InventoryReport(BaseModel):
    host_id: str
    hostname: str | None = None
    platform: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    packages: list[InventoryPackage] = Field(default_factory=list)


class Heartbeat(BaseModel):
    host_id: str
    hostname: str | None = None
    platform: str
    agent_version: str
    queue_depth: int = 0
    ip_address: str | None = None
    status: str = "online"
    metadata: dict[str, Any] = Field(default_factory=dict)


class ResponseActionCreate(BaseModel):
    host_id: str
    type: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    approval_mode: Literal["manual", "automatic"] = "manual"
    ttl: int = 900
    requested_by: str = "analyst"


class ActionApproval(BaseModel):
    approved_by: str = "analyst"


class ActionResult(BaseModel):
    state: Literal["completed", "failed", "expired"]
    result: dict[str, Any] = Field(default_factory=dict)


class OverviewMetric(BaseModel):
    label: str
    value: int
    trend: str


class DashboardSnapshot(BaseModel):
    metrics: list[OverviewMetric]
    alerts: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    vulnerabilities: list[dict[str, Any]]
    hosts: list[dict[str, Any]]


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict[str, Any]


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: str | None = None
    role: str = "analyst"


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: str | None
    role: str
    is_active: bool
    last_login: datetime | None
    created_at: datetime


class AuditLogResponse(BaseModel):
    id: int
    entity_type: str
    entity_id: str
    action: str
    actor: str
    occurred_at: datetime
    details: dict[str, Any]

