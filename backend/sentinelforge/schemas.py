import json
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Source = Literal["synthetic", "linux_auth", "auditd", "sysmon", "wazuh", "zeek"]
Severity = Literal["low", "medium", "high", "critical"]


def utc(value: Any) -> str:
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(value, timezone.utc)
    elif isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("timestamp must include a timezone or be a Unix timestamp")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


def now() -> str:
    return utc(datetime.now(timezone.utc))


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: Source
    sensor: str = Field(min_length=1, max_length=128)
    host: str | None = Field(default=None, max_length=255)
    timestamp: str | float | None = None
    payload: dict[str, Any] | str

    @field_validator("payload")
    @classmethod
    def size_limit(cls, value):
        if len(json.dumps(value).encode()) > 65_536:
            raise ValueError("payload exceeds 64 KiB")
        return value


class Batch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=200)


class Normalized(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    timestamp: str
    source: Source
    sensor: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    user: str | None = Field(default=None, max_length=255)
    kind: Literal["authentication", "process", "network", "account", "privilege", "other"]
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    process: str | None = Field(default=None, max_length=1024)
    command: str | None = Field(default=None, max_length=16384)
    parent: str | None = Field(default=None, max_length=1024)
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    external_id: str | None = Field(default=None, max_length=255)
    fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def timestamp_utc(cls, value):
        return utc(value)

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value)) if value is not None else None

    @field_validator("host", "user")
    @classmethod
    def identifiers(cls, value):
        return value.casefold() if value else value


class CasePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["open", "investigating", "escalated", "closed"] | None = None
    assignee: str | None = Field(default=None, max_length=80)


class NoteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=5000, pattern=r"\S")


class ResponseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["simulate_isolation"]
    reason: str = Field(min_length=10, max_length=1000)


class ChecklistInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key: Literal["validate_signal", "scope_hosts", "preserve_evidence", "review_response"]
    complete: bool
