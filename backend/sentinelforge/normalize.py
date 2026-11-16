"""Explicit adapters; unsupported or ambiguous shapes fail instead of inventing attribution."""

import re
import shlex
from typing import Any

from .schemas import Envelope, Normalized


def normalize(envelope: Envelope) -> Normalized:
    raw = envelope.payload
    p: dict[str, Any] = raw if isinstance(raw, dict) else {}
    base = dict(
        source=envelope.source,
        sensor=envelope.sensor,
        host=envelope.host,
        timestamp=envelope.timestamp,
        kind="other",
    )
    match envelope.source:
        case "synthetic":
            if not isinstance(raw, dict):
                raise ValueError("synthetic payload must be an object")
            base.update(p)
            base.update(source=envelope.source, sensor=envelope.sensor)
            if envelope.host:
                base["host"] = envelope.host
        case "linux_auth":
            line = raw if isinstance(raw, str) else p.get("message", "")
            prefix = re.match(r"^(\d{4}-\d\d-\d\dT\S+)\s+(\S+)\s+", line)
            if prefix:
                base.update(timestamp=prefix[1], host=envelope.host or prefix[2])
            ssh = re.search(
                r"(Failed|Accepted) (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)", line
            )
            sudo = re.search(
                r"(?:^|\s)sudo(?:\[\d+\])?:\s*(\S+)\s*:\s*(.*?)\bUSER=(\S+)\s*;.*?\bCOMMAND=(.+)",
                line,
            )
            if ssh:
                base.update(
                    kind="authentication",
                    user=ssh[2],
                    src_ip=ssh[3],
                    outcome="failure" if ssh[1] == "Failed" else "success",
                    fields={"service": "sshd"},
                )
            elif sudo:
                # sudo's accepted policy log has only metadata before USER;
                # rejected/error logs prepend a reason after the submitting user.
                # An accepted record proves authorization, not command completion.
                prefix_fields = sudo[2].strip()
                reason = prefix_fields.split(";", 1)[0].strip()
                accepted = re.fullmatch(r"(?:(?:TTY|CHROOT|PWD|HOST)=[^;]*;\s*)*", prefix_fields)
                denied = re.fullmatch(
                    r"user NOT in sudoers|user NOT authorized on host|command not allowed|"
                    r"\d+ incorrect password attempts?|a password is required|"
                    r"sorry, you are not allowed to set the following environment variables(?::.*)?",
                    reason,
                )
                authorization = "accepted" if accepted else "denied" if denied else "unknown"
                base.update(
                    kind="privilege",
                    user=sudo[1],
                    process="sudo",
                    command=sudo[4],
                    outcome="success" if accepted else "failure" if denied else "unknown",
                    fields={"target_user": sudo[3], "sudo_authorization": authorization},
                )
            else:
                raise ValueError("unsupported auth message; expected SSH authentication or sudo COMMAND")
        case "sysmon":
            if not p:
                raise ValueError("Sysmon requires JSON, not XML")
            event = p.get("Event", p)
            system = event.get("System", {})
            data = event.get("EventData", event)
            event_id = int(system.get("EventID", data.get("EventID", 0)))
            timestamp = data.get("UtcTime", envelope.timestamp)
            # Sysmon UtcTime is explicitly UTC even when its serialization lacks Z.
            if isinstance(timestamp, str) and not re.search(r"(?:Z|[+-]\d\d:\d\d)$", timestamp):
                timestamp += "+00:00"
            base.update(
                timestamp=timestamp,
                host=envelope.host or system.get("Computer") or data.get("Computer"),
                user=data.get("User"),
                external_id=str(system.get("EventRecordID", data.get("RecordID", ""))) or None,
                fields={"event_id": event_id},
            )
            if event_id == 1:
                base.update(
                    kind="process",
                    process=data.get("Image"),
                    command=data.get("CommandLine"),
                    parent=data.get("ParentImage"),
                )
                original = data.get("OriginalFileName")
                if original is not None:
                    if not isinstance(original, str) or len(original) > 255:
                        raise ValueError("invalid OriginalFileName observation")
                    base["fields"]["original_file_name"] = original
            elif event_id == 3:
                base.update(
                    kind="network",
                    process=data.get("Image"),
                    src_ip=data.get("SourceIp"),
                    dst_ip=data.get("DestinationIp"),
                    dst_port=data.get("DestinationPort"),
                )
            else:
                raise ValueError("supported Sysmon EventID values: 1 and 3")
        case "auditd":
            if isinstance(raw, str):
                epoch = re.search(r"audit\((\d+(?:\.\d+)?):(\d+)\)", raw)
                if not epoch:
                    raise ValueError("auditd record needs an audit(timestamp:serial) identifier")
                # Input is one already-assembled event, with records joined by newlines.
                pairs = {}
                for token in shlex.split(raw.replace("\n", " ")):
                    if "=" in token:
                        key, value = token.split("=", 1)
                        pairs[key] = value
                p = pairs
                p["timestamp"], p["serial"] = float(epoch[1]), epoch[2]
                args = [p[f"a{i}"] for i in range(128) if f"a{i}" in p]
                p["command"] = " ".join(args) or p.get("exe")
            if not p.get("exe"):
                raise ValueError("auditd needs assembled SYSCALL/EXECVE data with exe")
            base.update(
                timestamp=p.get("timestamp", envelope.timestamp),
                host=envelope.host or p.get("node"),
                kind="process",
                process=p["exe"],
                command=p.get("command"),
                user=str(p.get("auid", p.get("uid", ""))) or None,
                external_id=str(p["serial"]) if "serial" in p else None,
                outcome="success" if str(p.get("success")) in ("yes", "1", "True") else "unknown",
                fields={"uid": str(p.get("uid", "")), "euid": str(p.get("euid", ""))},
            )
        case "wazuh":
            if not p.get("agent", {}).get("name"):
                raise ValueError("Wazuh alert requires agent.name")
            data = p.get("data", {})
            base.update(
                timestamp=p.get("timestamp", envelope.timestamp),
                host=envelope.host or p["agent"]["name"],
                external_id=str(p["id"]) if "id" in p else None,
                fields={
                    "wazuh_rule_id": str(p.get("rule", {}).get("id", "")),
                    "wazuh_groups": p.get("rule", {}).get("groups", []),
                },
            )
            # Parse the underlying log; a Wazuh rule level is not a detection verdict here.
            if p.get("full_log") and p.get("decoder", {}).get("name", "").startswith(("sshd", "sudo")):
                converted = normalize(
                    Envelope(
                        source="linux_auth",
                        sensor=envelope.sensor,
                        host=base["host"],
                        timestamp=base["timestamp"],
                        payload=p["full_log"],
                    )
                )
                fields = converted.fields | base["fields"]
                base = converted.model_dump() | {
                    "source": "wazuh",
                    "external_id": base["external_id"],
                    "fields": fields,
                }
            elif data.get("win", {}).get("system"):
                win = data["win"]
                system, ed = win["system"], win.get("eventdata", {})
                mapped = {
                    "Event": {
                        "System": {"EventID": system.get("eventID"), "Computer": base["host"]},
                        "EventData": {
                            "UtcTime": base["timestamp"],
                            "Image": ed.get("image"),
                            "CommandLine": ed.get("commandLine"),
                            "ParentImage": ed.get("parentImage"),
                            "OriginalFileName": ed.get("originalFileName"),
                            "User": ed.get("user"),
                            "SourceIp": ed.get("sourceIp"),
                            "DestinationIp": ed.get("destinationIp"),
                            "DestinationPort": ed.get("destinationPort"),
                        },
                    }
                }
                converted = normalize(Envelope(source="sysmon", sensor=envelope.sensor, payload=mapped))
                base = converted.model_dump() | {
                    "source": "wazuh",
                    "external_id": base["external_id"],
                    "fields": converted.fields | base["fields"],
                }
            else:
                base.update(user=data.get("srcuser"), src_ip=data.get("srcip"))
        case "zeek":
            if "id.resp_h" not in p:
                raise ValueError("Zeek adapter requires conn.log JSON")
            base.update(
                timestamp=p.get("ts", envelope.timestamp),
                kind="network",
                src_ip=p.get("id.orig_h"),
                dst_ip=p["id.resp_h"],
                dst_port=p.get("id.resp_p"),
                external_id=p.get("uid"),
                fields={
                    "proto": p.get("proto"),
                    "service": p.get("service"),
                    "orig_bytes": p.get("orig_bytes", 0),
                    "conn_state": p.get("conn_state"),
                },
            )
    return Normalized.model_validate(base)
