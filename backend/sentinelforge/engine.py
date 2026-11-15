import hashlib
import json
from datetime import datetime, timedelta

from sqlalchemy import select

from .context import context_for_event, suppress_approved
from .db import Alert, Audit, Case, Event
from .process_evidence import process_evidence, uid_zero_argument
from .schemas import now, utc

RISK = {"low": 20, "medium": 40, "high": 65, "critical": 85}
GENERIC_USERS = {"root", "administrator", "system", "unknown", "0", "4294967295", "-1"}


def digest(data):
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def shift(timestamp, seconds):
    return utc(datetime.fromisoformat(timestamp) + timedelta(seconds=seconds))


def correlate(session, event, rule):
    candidates = session.scalars(
        select(Case)
        .where(
            Case.status != "closed",
            Case.last_seen >= shift(event.timestamp, -900),
            Case.first_seen <= shift(event.timestamp, 900),
        )
        .order_by(Case.last_seen.desc(), Case.id)
    ).all()
    known_user = event.user and event.user not in GENERIC_USERS
    host_matches = [c for c in candidates if event.host in c.hosts]
    user_matches = [c for c in candidates if known_user and event.user in c.users]
    if host_matches or user_matches:
        case = (host_matches or user_matches)[0]
        reason = f"Same {'host ' + event.host if host_matches else 'user ' + event.user}; within 15-minute case activity window."
        case.hosts = sorted(set(case.hosts + [event.host]))
        case.users = sorted(set(case.users + ([event.user] if known_user else [])))
        case.first_seen = min(case.first_seen, event.timestamp)
        case.last_seen = max(case.last_seen, event.timestamp)
    else:
        case = Case(
            title=f"{rule.meta['title']} · {event.host}",
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            hosts=[event.host],
            users=[event.user] if known_user else [],
        )
        session.add(case)
        session.flush()
        reason = "New case: no open host/user match within 15 minutes."
    return case, reason


def detect(session, event, rules, *, principal=None, stamp=None):
    stamp = utc(stamp or now())
    context = context_for_event(session, event, principal, stamp)
    process = process_evidence(event.data, context["script_indicator"])
    # Reserved booleans are computed in a temporary match view. Forged input
    # fields never control them, and raw/normalized evidence remains untouched.
    matching = event.data | {
        "fields": event.data.get("fields", {})
        | {
            "sf_powershell_encoded": process["powershell_encoded"],
            "sf_powershell_file_suspicious": process["powershell_file_suspicious"],
            "sf_https_indicator": context["https_indicator"] is not None,
            "sf_uid_zero": uid_zero_argument(event.data),
        }
    }
    emitted = []
    for rule in rules:
        if not rule.matches(matching):
            continue
        if suppress_approved(session, event, rule, principal, stamp, context):
            continue
        evidence = [event]
        group = digest([event.host, event.src_ip])
        aggregate = rule.extension.get("aggregate")
        if aggregate:
            if not event.src_ip:
                continue
            candidates = session.scalars(
                select(Event)
                .where(
                    Event.host == event.host,
                    Event.src_ip == event.src_ip,
                    Event.timestamp >= shift(event.timestamp, -300),
                    Event.timestamp <= shift(event.timestamp, 300),
                )
                .order_by(Event.timestamp, Event.id)
            ).all()
            candidates = [c for c in candidates if rule.matches(c.data)]
            evidence = []
            for start in candidates:
                window = [
                    c for c in candidates if start.timestamp <= c.timestamp <= shift(start.timestamp, 300)
                ]
                if len(window) >= 5 and event.id in {c.id for c in window}:
                    evidence = window
                    break
            if not evidence:
                continue
            anchor = max(e.timestamp for e in evidence)
            existing = session.scalar(
                select(Alert).where(
                    Alert.rule_id == rule.id,
                    Alert.group_key == group,
                    Alert.timestamp >= shift(anchor, -300),
                    Alert.timestamp <= shift(anchor, 300),
                )
            )
            if existing:
                existing.event_ids = sorted(set(existing.event_ids + [e.id for e in evidence]))
                existing.explanation = f"At least 5 SSH failures in a 300-second window on {event.host} from {event.src_ip}; related evidence retained."
                continue
        anchor = max(e.timestamp for e in evidence)
        case, reason = correlate(session, event, rule)
        explanation = (
            f"{len(evidence)} SSH failures in 300 seconds from {event.src_ip}."
            if aggregate
            else rule.extension["explanation"]
        )
        if rule.id in {"00000000-0000-0000-0000-000000000002", "00000000-0000-0000-0000-000000000008"}:
            explanation += " " + " ".join(process["details"])
        intel = (
            context["https_indicator"]
            if rule.id == "00000000-0000-0000-0000-000000000009"
            else (
                context["script_indicator"]
                if rule.id == "00000000-0000-0000-0000-000000000008" and process["script_indicator_matched"]
                else None
            )
        )
        if intel:
            explanation += (
                f" Indicator {intel['id']}; version {intel['version']}; provenance {intel['provenance']}; "
                f"binding {context['binding_id']}; valid [{intel['valid_from']}, {intel['valid_until']}); "
                f"expires {intel['expires_at']}."
            )
        alert = Alert(
            case_id=case.id,
            rule_id=rule.id,
            title=rule.meta["title"],
            severity=rule.meta["level"],
            confidence=rule.extension["confidence"],
            timestamp=anchor,
            host=event.host,
            user=event.user,
            group_key=group,
            techniques=rule.techniques,
            event_ids=[e.id for e in evidence],
            explanation=explanation[:2000],
            correlation_reason=reason,
        )
        session.add(alert)
        session.flush()
        if intel:
            session.add(
                Audit(
                    actor=principal,
                    action="detection.enriched",
                    case_id=case.id,
                    created_at=stamp,
                    detail={
                        "event_id": event.id,
                        "alert_id": alert.id,
                        "rule_id": rule.id,
                        "binding_id": context["binding_id"],
                        "indicator": intel,
                        "context_sha256": digest(intel),
                    },
                )
            )
        alerts = session.scalars(select(Alert).where(Alert.case_id == case.id)).all()
        techniques = {t for a in alerts for t in a.techniques}
        case.risk = min(
            100,
            max(RISK[a.severity] for a in alerts)
            + 5 * max(0, len(techniques) - 1)
            + min(15, 2 * (len(alerts) - 1)),
        )
        emitted.append(alert)
    return emitted
