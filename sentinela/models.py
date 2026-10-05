"""Data models shared across Sentinela."""
from datetime import datetime, timezone
from ipaddress import IPv4Address
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator

EventType = Literal[
    "process_creation",
    "authentication_success",
    "authentication_failure",
    "account_created",
    "network_connection",
]
Role = Literal["workstation", "server", "domain_controller", "web_server", "database"]
Criticality = Literal["low", "medium", "high"]
AlertStatus = Literal["new", "investigating", "closed"]
Verdict = Literal["true_positive", "false_positive"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# --- Organization ---

class AssetIn(BaseModel):
    """A computer or server in the simulated organization."""
    hostname: str = Field(min_length=1, max_length=63, pattern=r"^[A-Za-z0-9][A-Za-z0-9-]*$")
    ip: IPv4Address
    os: str = Field(min_length=1, max_length=60)
    role: Role
    department: str = Field("General", min_length=1, max_length=60)
    criticality: Criticality = "medium"
    users: list[str] = Field(default_factory=list)


class Asset(AssetIn):
    id: str


# --- Events ---

class TelemetryEvent(BaseModel):
    """Unified (normalized) event schema. Every event, simulated or real, uses this shape."""
    timestamp: datetime = Field(default_factory=utc_now)
    hostname: str
    event_type: EventType
    user: str
    source_ip: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    target_user: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    bytes_out: Optional[int] = None

    @field_validator("timestamp")
    @classmethod
    def assume_utc(cls, value: datetime) -> datetime:
        # Store every timestamp in UTC (no timezone = already UTC), so events can be compared and sorted
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


# --- API request bodies ---

class AttackRequest(BaseModel):
    scenario: str
    target_id: str
    source_id: Optional[str] = None
    succeed: bool = False


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    verdict: Optional[Verdict] = None
    notes: Optional[str] = Field(None, max_length=2000)


class SimulationSettings(BaseModel):
    running: Optional[bool] = None
    interval_seconds: Optional[float] = Field(None, ge=0.5, le=60)
