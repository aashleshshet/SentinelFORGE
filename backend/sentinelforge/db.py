from uuid import uuid4

from sqlalchemy import JSON, ForeignKey, Index, Integer, String, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from .schemas import now


def uid():
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    received_at: Mapped[str] = mapped_column(String(40), default=now)
    source: Mapped[str] = mapped_column(String(32), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    user: Mapped[str | None] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32))
    src_ip: Mapped[str | None] = mapped_column(String(45))
    data: Mapped[dict] = mapped_column(JSON)
    raw: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (Index("event_auth_window", "host", "src_ip", "kind", "timestamp"),)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(32), default="open")
    assignee: Mapped[str | None] = mapped_column(String(80))
    first_seen: Mapped[str] = mapped_column(String(40))
    last_seen: Mapped[str] = mapped_column(String(40), index=True)
    hosts: Mapped[list] = mapped_column(JSON)
    users: Mapped[list] = mapped_column(JSON)
    risk: Mapped[int] = mapped_column(Integer, default=0)
    checklist: Mapped[dict] = mapped_column(JSON, default=dict)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    host: Mapped[str] = mapped_column(String(255))
    user: Mapped[str | None] = mapped_column(String(255))
    group_key: Mapped[str] = mapped_column(String(400), index=True)
    techniques: Mapped[list] = mapped_column(JSON)
    event_ids: Mapped[list] = mapped_column(JSON)
    explanation: Mapped[str] = mapped_column(String(2000))
    correlation_reason: Mapped[str] = mapped_column(String(500))


class Note(Base):
    __tablename__ = "notes"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    author: Mapped[str] = mapped_column(String(80))
    text: Mapped[str] = mapped_column(String(5000))
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), index=True)
    actor: Mapped[str] = mapped_column(String(80))
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    sha256: Mapped[str] = mapped_column(String(64))
    snapshot: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    created_by: Mapped[str] = mapped_column(String(80))


class ResponseAction(Base):
    __tablename__ = "responses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id"), index=True)
    action: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(1000))
    requested_by: Mapped[str] = mapped_column(String(80))
    approved_by: Mapped[str | None] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    created_at: Mapped[str] = mapped_column(String(40), default=now)


class IOC(Base):
    __tablename__ = "iocs"
    value: Mapped[str] = mapped_column(String(255), primary_key=True)
    label: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(255))


class CollectorBinding(Base):
    __tablename__ = "collector_bindings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    principal: Mapped[str] = mapped_column(String(80), index=True)
    source: Mapped[str] = mapped_column(String(32))
    sensor: Mapped[str] = mapped_column(String(128))
    host: Mapped[str] = mapped_column(String(255))
    reason: Mapped[str] = mapped_column(String(1000))
    expires_at: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    created_by: Mapped[str] = mapped_column(String(80))
    revoked_at: Mapped[str | None] = mapped_column(String(40))
    revoked_by: Mapped[str | None] = mapped_column(String(80))


class DetectionApproval(Base):
    __tablename__ = "detection_approvals"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    binding_id: Mapped[str] = mapped_column(ForeignKey("collector_bindings.id"), index=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    user: Mapped[str] = mapped_column(String(255))
    command_sha256: Mapped[str] = mapped_column(String(64))
    valid_from: Mapped[str] = mapped_column(String(40))
    valid_until: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[str] = mapped_column(String(40))
    reason: Mapped[str] = mapped_column(String(1000))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    created_by: Mapped[str] = mapped_column(String(80))
    used_event_id: Mapped[str | None] = mapped_column(ForeignKey("events.id"))
    used_at: Mapped[str | None] = mapped_column(String(40))
    revoked_at: Mapped[str | None] = mapped_column(String(40))
    revoked_by: Mapped[str | None] = mapped_column(String(80))
    __table_args__ = (
        UniqueConstraint("binding_id", "rule_id", "user", "command_sha256", "valid_from", "valid_until"),
    )


class ContextReceipt(Base):
    """An attributed contextual evaluation, separate from exact event deduplication."""

    __tablename__ = "context_receipts"
    event_id: Mapped[str] = mapped_column(ForeignKey("events.id"), primary_key=True)
    principal: Mapped[str] = mapped_column(String(80), primary_key=True)
    evaluated_at: Mapped[str] = mapped_column(String(40))


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(255), index=True)
    purpose: Mapped[str] = mapped_column(String(32))
    version: Mapped[str] = mapped_column(String(128))
    provenance: Mapped[str] = mapped_column(String(1000))
    reason: Mapped[str] = mapped_column(String(1000))
    valid_from: Mapped[str] = mapped_column(String(40))
    valid_until: Mapped[str] = mapped_column(String(40))
    expires_at: Mapped[str] = mapped_column(String(40))
    created_at: Mapped[str] = mapped_column(String(40), default=now)
    created_by: Mapped[str] = mapped_column(String(80))
    revoked_at: Mapped[str | None] = mapped_column(String(40))
    revoked_by: Mapped[str | None] = mapped_column(String(80))
    __table_args__ = (UniqueConstraint("kind", "value", "purpose", "version"),)


def database(url: str):
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        if ":memory:" in url:
            kwargs["poolclass"] = StaticPool
    engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def sqlite_config(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")

    Base.metadata.create_all(engine)
    return engine, sessionmaker(engine, expire_on_commit=False)


def serialize(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}
