"""Authenticated operator context; telemetry never grants its own exemption.

An enrollment binds an authenticated principal to an asserted sensor/host scope.
It does not cryptographically prove the physical host or protect a compromised
collector. All times use a server clock; the callable is injectable only in code
for explicitly dated, reproducible tests, never through HTTP or environment.
"""

import hashlib
import ipaddress
import json
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select

from .db import Audit, CollectorBinding, DetectionApproval, ThreatIndicator, serialize
from .schemas import Source, utc

APPROVABLE_RULES = {
    "00000000-0000-0000-0000-000000000002",
    "00000000-0000-0000-0000-000000000004",
}


def command_digest(command: str) -> str:
    """Exact normalized command UTF-8 bytes; no shell interpretation or case folding."""
    return hashlib.sha256(command.encode()).hexdigest()


class ContextInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    expires_at: str
    reason: str = Field(min_length=10, max_length=1000)

    @field_validator("expires_at", mode="before")
    @classmethod
    def timestamp(cls, value):
        return utc(value)


class BindingInput(ContextInput):
    principal: str = Field(pattern=r"^[a-zA-Z0-9_.@-]{1,80}$")
    source: Source
    sensor: str = Field(min_length=1, max_length=128)
    host: str = Field(min_length=1, max_length=255)

    @field_validator("host")
    @classmethod
    def identifier(cls, value):
        return value.casefold()


class WindowInput(ContextInput):
    valid_from: str
    valid_until: str

    @field_validator("valid_from", "valid_until", mode="before")
    @classmethod
    def window_timestamp(cls, value):
        return utc(value)

    @model_validator(mode="after")
    def interval(self):
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from; windows are half-open")
        return self


class ApprovalInput(WindowInput):
    binding_id: str = Field(min_length=1, max_length=36)
    rule_id: str
    user: str = Field(min_length=1, max_length=255)
    command_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")

    @field_validator("rule_id")
    @classmethod
    def rule(cls, value):
        if value not in APPROVABLE_RULES:
            raise ValueError("only encoded PowerShell and scheduled-task action approvals are supported")
        return value

    @field_validator("user", "command_sha256")
    @classmethod
    def lower(cls, value):
        return value.casefold()

    @model_validator(mode="after")
    def bounded_window(self):
        seconds = (
            datetime.fromisoformat(self.valid_until) - datetime.fromisoformat(self.valid_from)
        ).total_seconds()
        if seconds > 86400:
            raise ValueError("an action approval window cannot exceed 24 hours")
        return self


class IndicatorInput(WindowInput):
    kind: Literal["ip", "sha256"]
    value: str = Field(min_length=1, max_length=255)
    purpose: Literal["https-c2", "powershell-script"]
    version: str = Field(min_length=1, max_length=128)
    provenance: str = Field(min_length=10, max_length=1000)

    @model_validator(mode="after")
    def supported_indicator(self):
        if self.kind == "ip":
            address = ipaddress.ip_address(self.value)
            if self.purpose != "https-c2" or not address.is_global:
                raise ValueError("HTTPS indicators require a public IP address and https-c2 purpose")
            self.value = str(address)
        elif self.purpose != "powershell-script" or not re.fullmatch(r"[a-fA-F0-9]{64}", self.value):
            raise ValueError(
                "script indicators require an exact SHA-256 digest and powershell-script purpose"
            )
        else:
            self.value = self.value.casefold()
        return self


def active_bindings(db, event, principal, stamp):
    if not principal:
        return []
    return db.scalars(
        select(CollectorBinding)
        .where(
            CollectorBinding.principal == principal,
            CollectorBinding.source == event.source,
            CollectorBinding.sensor == event.data["sensor"],
            CollectorBinding.host == event.host,
            CollectorBinding.revoked_at.is_(None),
            CollectorBinding.expires_at > stamp,
        )
        .order_by(CollectorBinding.created_at, CollectorBinding.id)
    ).all()


def context_for_event(db, event, principal, stamp):
    """Return separate server-derived evidence; never change normalized/raw data."""
    bindings = active_bindings(db, event, principal, stamp)
    result = {
        "bindings": bindings,
        "binding_id": bindings[0].id if bindings else None,
        "script_indicator": None,
        "https_indicator": None,
    }
    if not bindings:
        return result
    fields = event.data.get("fields", {})
    script_hash = fields.get("script_sha256")
    # Sysmon process Hashes refer to the interpreter image, not its script file.
    script = (
        event.source == "synthetic"
        and isinstance(script_hash, str)
        and re.fullmatch(r"[a-fA-F0-9]{64}", script_hash)
    )
    network = event.kind == "network" and event.data.get("dst_port") == 443 and event.data.get("dst_ip")
    if not script and not network:
        return result
    for kind, value, purpose, target in [
        ("sha256", script_hash.casefold() if script else None, "powershell-script", "script_indicator"),
        ("ip", event.data.get("dst_ip") if network else None, "https-c2", "https_indicator"),
    ]:
        if value is None:
            continue
        row = db.scalar(
            select(ThreatIndicator)
            .where(
                ThreatIndicator.kind == kind,
                ThreatIndicator.value == value,
                ThreatIndicator.purpose == purpose,
                ThreatIndicator.valid_from <= event.timestamp,
                ThreatIndicator.valid_until > event.timestamp,
                ThreatIndicator.expires_at > stamp,
                ThreatIndicator.revoked_at.is_(None),
            )
            .order_by(ThreatIndicator.created_at.desc(), ThreatIndicator.id)
        )
        if row:
            result[target] = serialize(row)
    return result


def suppress_approved(db, event, rule, principal, stamp, context):
    """Consume one exact action approval atomically inside the ingestion transaction."""
    command = event.data.get("command")
    if rule.id not in APPROVABLE_RULES or not context["bindings"] or not command or not event.user:
        return False
    command_sha256 = command_digest(command)
    approval = db.scalar(
        select(DetectionApproval)
        .where(
            DetectionApproval.binding_id.in_([binding.id for binding in context["bindings"]]),
            DetectionApproval.rule_id == rule.id,
            DetectionApproval.user == event.user,
            DetectionApproval.command_sha256 == command_sha256,
            DetectionApproval.valid_from <= event.timestamp,
            DetectionApproval.valid_until > event.timestamp,
            DetectionApproval.expires_at > stamp,
            DetectionApproval.revoked_at.is_(None),
            DetectionApproval.used_event_id.is_(None),
        )
        .order_by(DetectionApproval.created_at, DetectionApproval.id)
    )
    if not approval:
        return False
    binding = next(item for item in context["bindings"] if item.id == approval.binding_id)
    snapshot = {"approval": serialize(approval), "binding": serialize(binding)}
    context_sha256 = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    approval.used_event_id, approval.used_at = event.id, stamp
    db.add(
        Audit(
            actor=principal,
            action="detection.suppressed",
            created_at=stamp,
            detail={
                "event_id": event.id,
                "rule_id": rule.id,
                "approval_id": approval.id,
                "binding_id": binding.id,
                "command_sha256": command_sha256,
                "context_sha256": context_sha256,
                "context": snapshot,
                "reason": approval.reason,
                "decision": "single-use exact action approval",
            },
        )
    )
    db.flush()
    return True
