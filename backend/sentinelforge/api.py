import hmac
import ipaddress
import json
import logging
import threading
import time
from collections import Counter, OrderedDict, deque
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import func, or_, select, text

from .config import ROOT, Identity, Settings
from .db import IOC, Alert, Audit, Case, Event, Evidence, Note, ResponseAction, database, serialize
from .engine import detect, digest
from .normalize import normalize
from .rules import load_rules
from .schemas import Batch, CasePatch, ChecklistInput, Envelope, NoteInput, ResponseInput, now

logger = logging.getLogger("sentinelforge")


class Guardrails:
    """Single-process IP limiter and streaming body cap, before JSON parsing."""

    def __init__(self, app, settings):
        self.app, self.settings, self.clients = app, settings, OrderedDict()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        if self.settings.public_demo and scope["method"] not in {"GET", "HEAD", "OPTIONS"}:
            return await JSONResponse(
                {"detail": "Public demo is read-only. Run locally to investigate your own data."}, 403
            )(scope, receive, send)
        start = time.perf_counter()
        request_id = str(uuid4())
        if scope["path"].startswith("/api/") and scope["path"] != "/api/health":
            client = (scope.get("client") or ("unknown",))[0]
            stamp = time.monotonic()
            queue = self.clients.setdefault(client, deque())
            self.clients.move_to_end(client)
            while queue and queue[0] < stamp - 60:
                queue.popleft()
            if len(queue) >= self.settings.rate_limit:
                return await JSONResponse(
                    {"detail": "Rate limit exceeded"}, 429, headers={"Retry-After": "60"}
                )(scope, receive, send)
            queue.append(stamp)
            if len(self.clients) > 10000:
                self.clients.popitem(last=False)
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.settings.max_body_bytes:
                return await JSONResponse({"detail": "Request body exceeds limit"}, 413)(scope, receive, send)
            if not message.get("more_body", False):
                break
        delivered = False

        async def limited_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        async def guarded_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", [])) + [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cache-control", b"no-store"),
                    (b"x-request-id", request_id.encode()),
                    (
                        b"content-security-policy",
                        b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                    ),
                ]
                message["headers"] = headers
                # No query strings, raw telemetry, notes, Authorization or credentials in logs.
                logger.info(
                    json.dumps(
                        {
                            "request_id": request_id,
                            "method": scope["method"],
                            "status": message["status"],
                            "duration_ms": round((time.perf_counter() - start) * 1000, 2),
                        }
                    )
                )
            await send(message)

        await self.app(scope, limited_receive, guarded_send)


class IOCInput(BaseModel):
    value: str
    label: str = Field(min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=255)


def create_app(settings: Settings | None = None):
    settings = settings or Settings()
    app = FastAPI(title="SentinelForge", version="0.1.0", docs_url=None, redoc_url=None)
    app.add_middleware(Guardrails, settings=settings)
    app.state.engine, factory = database(settings.database_url)
    app.state.sessions = factory
    if settings.public_demo:
        from .public_demo import load_snapshot

        load_snapshot(app.state.engine)
    rules = load_rules(settings.rules_path)
    attack = (
        json.loads(settings.attack_path.read_text()) if settings.attack_path.exists() else {"objects": []}
    )
    techniques = {}
    for obj in attack["objects"]:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                techniques[ref["external_id"]] = {
                    "id": ref["external_id"],
                    "name": obj["name"],
                    "url": ref.get("url"),
                    "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                }
    lock = threading.RLock()
    security = HTTPBearer(auto_error=False)

    def identity(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(security)):
        if settings.public_demo:
            return Identity(
                name="demo-visitor", role="viewer", token="public-demo-unused-placeholder-no-credential"
            )
        if settings.local_mode and not request.headers.get("authorization"):
            peer = request.client.host if request.client else ""
            host = urlsplit("http://" + request.headers.get("host", "")).hostname
            try:
                loopback = ipaddress.ip_address(peer).is_loopback
            except ValueError:
                loopback = False
            origin = request.headers.get("origin")
            if (
                not loopback
                or host not in {"127.0.0.1", "localhost", "::1"}
                or request.headers.get("sec-fetch-site") == "cross-site"
                or (origin and origin != str(request.base_url).rstrip("/"))
            ):
                raise HTTPException(403, "Local mode accepts same-origin loopback requests only")
            return Identity(
                name="__local__", role="admin", token="local-mode-unused-placeholder-no-auth-credential"
            )
        if credentials and credentials.scheme.lower() == "bearer":
            for principal in settings.identities:
                if hmac.compare_digest(credentials.credentials, principal.token.get_secret_value()):
                    return principal
        raise HTTPException(401, "Valid bearer token required", headers={"WWW-Authenticate": "Bearer"})

    def roles(*allowed):
        def check(principal=Depends(identity)):
            if principal.role not in allowed:
                raise HTTPException(403, "Role does not permit this operation")
            return principal

        return check

    read = roles("viewer", "analyst", "admin")
    analyst = roles("analyst", "admin")
    admin = roles("admin")
    ingest = roles("ingest", "admin")
    evidence_read = read if settings.public_demo else analyst

    def session():
        with factory() as value:
            yield value

    @contextmanager
    def mutation(db):
        # All writes take the same lock; PostgreSQL extends serialization across processes.
        with lock:
            try:
                if app.state.engine.dialect.name == "postgresql":
                    db.execute(text("SELECT pg_advisory_xact_lock(723101)"))
                yield
                db.commit()
            except Exception:
                db.rollback()
                raise

    def audit(db, actor, action, case_id=None, **detail):
        db.add(Audit(actor=actor.name, action=action, case_id=case_id, detail=detail))

    def get_case(db, case_id):
        value = db.get(Case, case_id)
        if value is None:
            raise HTTPException(404, "Case not found")
        return value

    def ingest_batch(batch, db, actor):
        result = {"accepted": 0, "duplicates": 0, "rejected": 0, "alerts_created": 0, "results": []}
        with mutation(db):
            for index, item in enumerate(batch.events):
                try:
                    envelope = Envelope.model_validate(item)
                    normalized = normalize(envelope)
                    data = normalized.model_dump()
                    if data["dst_ip"]:
                        data["fields"] = data["fields"] | {
                            "destination_scope": "public"
                            if ipaddress.ip_address(data["dst_ip"]).is_global
                            else "nonpublic"
                        }
                    raw = envelope.model_dump()
                    fingerprint = digest({"normalized": data, "payload": raw["payload"]})
                except (
                    ValidationError,
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OverflowError,
                ) as error:
                    # Parser exceptions are handled before DB operations; programming/database errors propagate.
                    if not isinstance(error, (ValidationError, ValueError, OverflowError)):
                        detail = "Unsupported payload shape or missing required fields"
                    elif isinstance(error, ValidationError):
                        detail = "; ".join(
                            ".".join(map(str, e["loc"])) + ": " + e["type"] for e in error.errors()
                        )
                    else:
                        detail = "Invalid timestamp, address, or unsupported telemetry format"
                    result["rejected"] += 1
                    result["results"].append({"index": index, "status": "rejected", "error": detail})
                    continue
                existing = db.scalar(select(Event).where(Event.fingerprint == fingerprint))
                if existing:
                    result["duplicates"] += 1
                    result["results"].append({"index": index, "status": "duplicate", "event_id": existing.id})
                    continue
                event = Event(
                    fingerprint=fingerprint,
                    timestamp=data["timestamp"],
                    source=data["source"],
                    host=data["host"],
                    user=data["user"],
                    kind=data["kind"],
                    src_ip=data["src_ip"],
                    data=data,
                    raw=raw,
                )
                db.add(event)
                db.flush()
                emitted = detect(db, event, rules)
                result["accepted"] += 1
                result["alerts_created"] += len(emitted)
                result["results"].append(
                    {
                        "index": index,
                        "status": "accepted",
                        "event_id": event.id,
                        "alert_ids": [a.id for a in emitted],
                    }
                )
            audit(
                db,
                actor,
                "ingest",
                accepted=result["accepted"],
                duplicates=result["duplicates"],
                rejected=result["rejected"],
            )
        return result

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.get("/api/me")
    def me(actor=Depends(read)):
        result = {"name": actor.name, "role": actor.role, "local": actor.name == "__local__"}
        if settings.public_demo:
            result["demo"] = True
        return result

    @app.post("/api/ingest")
    def ingest_events(batch: Batch, db=Depends(session), actor=Depends(ingest)):
        return ingest_batch(batch, db, actor)

    @app.post("/api/demo")
    def demo(db=Depends(session), actor=Depends(admin)):
        return ingest_batch(Batch.model_validate_json((ROOT / "data/demo.json").read_text()), db, actor)

    @app.get("/api/events")
    def events(
        q: str = Query("", max_length=200),
        source: str | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        db=Depends(session),
        actor=Depends(read),
    ):
        query = select(Event)
        if q:
            query = query.where(
                or_(
                    Event.host.icontains(q, autoescape=True),
                    Event.user.icontains(q, autoescape=True),
                    Event.kind.icontains(q, autoescape=True),
                )
            )
        if source:
            query = query.where(Event.source == source)
        total = db.scalar(select(func.count()).select_from(query.subquery()))
        rows = db.scalars(query.order_by(Event.timestamp.desc(), Event.id).limit(limit).offset(offset)).all()
        return {"total": total, "items": [{"id": e.id, "received_at": e.received_at, **e.data} for e in rows]}

    @app.get("/api/events/{event_id}")
    def event_detail(event_id: str, db=Depends(session), actor=Depends(evidence_read)):
        row = db.get(Event, event_id)
        if not row:
            raise HTTPException(404, "Event not found")
        return serialize(row)

    @app.get("/api/alerts")
    def alerts(
        q: str = Query("", max_length=200),
        severity: str | None = None,
        technique: str | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        db=Depends(session),
        actor=Depends(read),
    ):
        query = select(Alert)
        if q:
            query = query.where(
                or_(
                    Alert.host.icontains(q, autoescape=True),
                    Alert.title.icontains(q, autoescape=True),
                    Alert.user.icontains(q, autoescape=True),
                )
            )
        if severity:
            query = query.where(Alert.severity == severity)
        rows = db.scalars(query.order_by(Alert.timestamp.desc(), Alert.id)).all()
        priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        rows.sort(key=lambda alert: priority[alert.severity], reverse=True)
        if technique:
            rows = [a for a in rows if technique in a.techniques]
        return {"total": len(rows), "items": [serialize(a) for a in rows[offset : offset + limit]]}

    @app.get("/api/cases")
    def cases(
        q: str = Query("", max_length=200),
        status: str | None = None,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        db=Depends(session),
        actor=Depends(read),
    ):
        query = select(Case)
        if q:
            query = query.where(Case.title.icontains(q, autoescape=True))
        if status:
            query = query.where(Case.status == status)
        total = db.scalar(select(func.count()).select_from(query.subquery()))
        return {
            "total": total,
            "items": [
                serialize(c)
                for c in db.scalars(
                    query.order_by(Case.risk.desc(), Case.last_seen.desc(), Case.id)
                    .limit(limit)
                    .offset(offset)
                )
            ],
        }

    def case_detail(db, case_id):
        case = get_case(db, case_id)
        alerts = db.scalars(
            select(Alert).where(Alert.case_id == case_id).order_by(Alert.timestamp, Alert.id)
        ).all()
        ids = sorted({eid for alert in alerts for eid in alert.event_ids})
        timeline = (
            db.scalars(select(Event).where(Event.id.in_(ids)).order_by(Event.timestamp, Event.id)).all()
            if ids
            else []
        )
        return {
            **serialize(case),
            "alerts": [serialize(a) for a in alerts],
            "timeline": [{"id": e.id, "fingerprint": e.fingerprint, **e.data} for e in timeline],
            "notes": [
                serialize(n)
                for n in db.scalars(
                    select(Note).where(Note.case_id == case_id).order_by(Note.created_at, Note.id)
                )
            ],
            "responses": [
                serialize(r)
                for r in db.scalars(
                    select(ResponseAction)
                    .where(ResponseAction.case_id == case_id)
                    .order_by(ResponseAction.created_at)
                )
            ],
            "evidence": [
                {k: v for k, v in serialize(e).items() if k != "snapshot"}
                for e in db.scalars(select(Evidence).where(Evidence.case_id == case_id))
            ],
        }

    @app.get("/api/cases/{case_id}")
    def case(case_id: str, db=Depends(session), actor=Depends(read)):
        return case_detail(db, case_id)

    @app.patch("/api/cases/{case_id}")
    def patch(case_id: str, change: CasePatch, db=Depends(session), actor=Depends(analyst)):
        with mutation(db):
            case = get_case(db, case_id)
            if "assignee" in change.model_fields_set:
                if (
                    change.assignee
                    and not (settings.local_mode and change.assignee == "__local__")
                    and change.assignee
                    not in {p.name for p in settings.identities if p.role in ("analyst", "admin")}
                ):
                    raise HTTPException(422, "Assignee must be a configured analyst or admin")
                case.assignee = change.assignee or None
            if change.status:
                case.status = change.status
            audit(db, actor, "case.update", case_id, changes=change.model_dump(exclude_unset=True))
        return serialize(case)

    @app.post("/api/cases/{case_id}/notes", status_code=201)
    def note(case_id: str, body: NoteInput, db=Depends(session), actor=Depends(analyst)):
        with mutation(db):
            get_case(db, case_id)
            row = Note(case_id=case_id, author=actor.name, text=body.text)
            db.add(row)
            audit(db, actor, "note.add", case_id)
        return serialize(row)

    @app.put("/api/cases/{case_id}/checklist")
    def checklist(case_id: str, body: ChecklistInput, db=Depends(session), actor=Depends(analyst)):
        with mutation(db):
            case = get_case(db, case_id)
            case.checklist = case.checklist | {body.key: body.complete}
            audit(db, actor, "checklist.update", case_id, **body.model_dump())
        return case.checklist

    @app.post("/api/cases/{case_id}/evidence", status_code=201)
    def preserve(case_id: str, db=Depends(session), actor=Depends(analyst)):
        with mutation(db):
            detail = case_detail(db, case_id)
            ids = [e["id"] for e in detail["timeline"]]
            raw = [
                serialize(e)
                for e in db.scalars(
                    select(Event).where(Event.id.in_(ids)).order_by(Event.timestamp, Event.id)
                )
            ]
            snapshot = {"schema_version": 1, "preserved_at": now(), "case": detail, "events": raw}
            evidence = Evidence(
                case_id=case_id, snapshot=snapshot, sha256=digest(snapshot), created_by=actor.name
            )
            db.add(evidence)
            audit(db, actor, "evidence.preserve", case_id, sha256=evidence.sha256)
        return {k: v for k, v in serialize(evidence).items() if k != "snapshot"}

    @app.get("/api/evidence/{evidence_id}/export")
    def export(evidence_id: str, db=Depends(session), actor=Depends(evidence_read)):
        with mutation(db):
            evidence = db.get(Evidence, evidence_id)
            if not evidence:
                raise HTTPException(404, "Evidence not found")
            if digest(evidence.snapshot) != evidence.sha256:
                raise HTTPException(409, "Evidence integrity verification failed")
            if not settings.public_demo:
                audit(db, actor, "evidence.export", evidence.case_id, evidence_id=evidence.id)
        return JSONResponse(
            {"sha256": evidence.sha256, "snapshot": evidence.snapshot},
            headers={"Content-Disposition": f'attachment; filename="case-{evidence.case_id}.json"'},
        )

    @app.post("/api/cases/{case_id}/responses", status_code=201)
    def response(case_id: str, body: ResponseInput, db=Depends(session), actor=Depends(analyst)):
        with mutation(db):
            get_case(db, case_id)
            row = ResponseAction(
                case_id=case_id, action=body.action, reason=body.reason, requested_by=actor.name
            )
            db.add(row)
            audit(db, actor, "response.request", case_id, action_type=body.action)
        return serialize(row)

    @app.post("/api/responses/{response_id}/approve")
    def approve(response_id: str, db=Depends(session), actor=Depends(admin)):
        with mutation(db):
            row = db.get(ResponseAction, response_id)
            if not row:
                raise HTTPException(404, "Response request not found")
            if row.requested_by == actor.name:
                raise HTTPException(403, "A different administrator must approve the request")
            if row.status != "pending":
                raise HTTPException(409, "Response already handled")
            row.approved_by, row.status = actor.name, "simulated"
            audit(
                db,
                actor,
                "response.simulated",
                row.case_id,
                response_id=row.id,
                outcome="Simulation only: no endpoint command or network action was executed",
            )
        return serialize(row)

    @app.get("/api/audit")
    def audit_list(
        case_id: str | None = None,
        limit: int = Query(100, ge=1, le=500),
        db=Depends(session),
        actor=Depends(analyst),
    ):
        query = select(Audit)
        if case_id:
            query = query.where(Audit.case_id == case_id)
        return {
            "items": [
                serialize(a)
                for a in db.scalars(query.order_by(Audit.created_at.desc(), Audit.id).limit(limit))
            ]
        }

    @app.get("/api/rules")
    def rule_list(db=Depends(session), actor=Depends(read)):
        counts = dict(db.execute(select(Alert.rule_id, func.count()).group_by(Alert.rule_id)).all())
        return {
            "items": [
                {
                    **r.meta,
                    "techniques": [
                        techniques.get(t, {"id": t, "name": "Metadata unavailable"}) for t in r.techniques
                    ],
                    "alert_count": counts.get(r.id, 0),
                }
                for r in rules
            ]
        }

    @app.get("/api/stats")
    def stats(db=Depends(session), actor=Depends(read)):
        alerts = db.scalars(select(Alert)).all()
        counts = Counter(a.severity for a in alerts)
        coverage = Counter(t for a in alerts for t in a.techniques)
        sources = {
            source: {"count": count, "last_received": latest}
            for source, count, latest in db.execute(
                select(Event.source, func.count(), func.max(Event.received_at)).group_by(Event.source)
            ).all()
        }
        hosts = [
            {"host": host, "events": count, "alerts": sum(a.host == host for a in alerts)}
            for host, count in db.execute(
                select(Event.host, func.count()).group_by(Event.host).order_by(func.count().desc()).limit(12)
            )
        ]
        return {
            "events": db.scalar(select(func.count()).select_from(Event)),
            "alerts": len(alerts),
            "open_cases": db.scalar(select(func.count()).select_from(Case).where(Case.status != "closed")),
            "rules": len(rules),
            "severity": {level: counts[level] for level in ("critical", "high", "medium", "low")},
            "sources": [
                {"source": s, **sources.get(s, {"count": 0, "last_received": None})}
                for s in ("linux_auth", "auditd", "sysmon", "wazuh", "zeek", "synthetic")
            ],
            "techniques": [
                {**techniques.get(t, {"id": t, "name": "Metadata unavailable"}), "alerts": coverage[t]}
                for t in sorted({t for r in rules for t in r.techniques})
            ],
            "hosts": hosts,
            "first_event": db.scalar(select(func.min(Event.timestamp))),
            "last_event": db.scalar(select(func.max(Event.timestamp))),
            "updated_at": now(),
            "scope": "Synthetic demo snapshot" if settings.public_demo else "All retained telemetry",
        }

    @app.put("/api/iocs")
    def put_ioc(body: IOCInput, db=Depends(session), actor=Depends(admin)):
        try:
            value = str(ipaddress.ip_address(body.value))
        except ValueError:
            raise HTTPException(422, "Local IOC store accepts IP addresses only") from None
        with mutation(db):
            row = db.get(IOC, value)
            if row:
                row.label, row.source = body.label, body.source
            else:
                row = IOC(value=value, label=body.label, source=body.source)
                db.add(row)
            audit(db, actor, "ioc.upsert", value=value)
        return serialize(row)

    @app.get("/api/iocs/lookup")
    def lookup(value: str = Query(max_length=255), db=Depends(session), actor=Depends(read)):
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            raise HTTPException(422, "Expected an IP address") from None
        row = db.get(IOC, value)
        return {"value": value, "match": serialize(row) if row else None, "external_requests": 0}

    # API routes precede the built frontend. No CORS wildcard or cross-site cookies.
    if Path(settings.frontend_path).is_dir():
        app.mount("/", StaticFiles(directory=settings.frontend_path, html=True), name="dashboard")
    return app
