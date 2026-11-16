"""Rebuild the deterministic, labeled toy corpus. No commands in it are executed."""

import json
from pathlib import Path
from uuid import UUID

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFINITIONS = [
    (
        "ssh-brute-force",
        "SSH password guessing",
        "high",
        "T1110.001",
        85,
        {
            "selection": {"kind": "authentication", "outcome": "failure", "fields.service": "sshd"},
            "condition": "selection",
        },
        "Five failed SSH authentications from the same IP on the same host within 300 seconds.",
        ["Bastions shared by many users", "Misconfigured automation with stale credentials"],
        ["host", "timestamp", "src_ip", "outcome", "fields.service"],
        {"count": 5, "seconds": 300, "group_by": ["host", "src_ip"]},
    ),
    (
        "powershell-encoded",
        "Suspicious PowerShell arguments",
        "high",
        "T1059.001",
        75,
        {
            "selection": {
                "kind": "process",
                "fields.sf_powershell_encoded": True,
            },
            "condition": "selection",
        },
        "PowerShell engine arguments contain an encoded-command option or inline download/decode marker; bounded parsing never executes content. Intent requires review.",
        ["Administrative encoded scripts", "Software deployment agents"],
        ["process", "command"],
        None,
    ),
    (
        "shell-unusual",
        "Shell with a TCP redirection",
        "high",
        "T1059.004",
        80,
        {
            "selection": {
                "kind": "process",
                "process|endswith": ["/bash", "/sh", "/zsh"],
                "command|contains": "/dev/tcp/",
            },
            "condition": "selection",
        },
        "Unix shell command contains /dev/tcp/ redirection; investigate process context.",
        ["Shell-based network diagnostics"],
        ["process", "command"],
        None,
    ),
    (
        "scheduled-task",
        "Scheduled task creation",
        "medium",
        "T1053.005",
        65,
        {
            "selection": {
                "kind": "process",
                "fields.sf_scheduled_task_create": True,
            },
            "condition": "selection",
        },
        "schtasks.exe requests task creation. This is a persistence-capable action, not proof of success or malicious intent.",
        ["Approved scheduled maintenance", "Installers"],
        ["process", "command"],
        None,
    ),
    (
        "account-uid-zero",
        "UID-zero account creation",
        "critical",
        "T1136.001",
        90,
        {
            "selection": {
                "kind": "process",
                "fields.sf_uid_zero": True,
            },
            "condition": "selection",
        },
        "useradd explicitly requests UID 0, creating a root-equivalent local identity if it succeeds.",
        ["Recovery procedures", "Isolated test systems"],
        ["process", "command"],
        None,
    ),
    (
        "sudo-shell",
        "Root shell through sudo",
        "medium",
        "T1548.003",
        60,
        {
            "selection": {
                "kind": "privilege",
                "fields.sf_sudo_shell": True,
            },
            "condition": "selection",
        },
        "An accepted sudo request names a supported shell executable as root. Authorization does not prove execution completion or an interactive session; compare against approved duties.",
        ["Authorized system administration"],
        ["user", "command", "fields.target_user"],
        None,
    ),
    (
        "outbound-port",
        "Outbound connection on an uncommon port",
        "medium",
        "T1571",
        45,
        {
            "selection": {
                "kind": "network",
                "fields.destination_scope": "public",
                "dst_port": [1337, 4444, 31337],
            },
            "condition": "selection",
        },
        "Connection to a globally routable IP on a configured uncommon port. Port alone does not establish C2.",
        ["Approved nonstandard services", "Security lab traffic"],
        ["dst_ip", "dst_port"],
        None,
    ),
]

# These rules use server-derived context, never telemetry-provided verdict flags.
# The original seven-rule demo and eighteen legacy scenarios remain unchanged.
DEFINITIONS += [
    (
        "powershell-file-context",
        "PowerShell file execution with supporting evidence",
        "high",
        "T1059.001",
        80,
        {
            "selection": {"kind": "process", "fields.sf_powershell_file_suspicious": True},
            "condition": "selection",
        },
        "PowerShell -File execution has an observed script hash matched to active operator intelligence, or Office ancestry with a bypass/hidden engine option. This is a scoped signal, not proof of compromise.",
        [
            "Security lab exercises",
            "Office automation using hidden or bypass options",
            "Incorrect operator intelligence",
        ],
        [
            "process",
            "command",
            "parent",
            "fields.original_file_name",
            "fields.script_path",
            "fields.script_sha256",
        ],
        None,
    ),
    (
        "https-context",
        "Port 443 destination matches active scoped intelligence",
        "high",
        "T1071.001",
        80,
        {"selection": {"kind": "network", "fields.sf_https_indicator": True}, "condition": "selection"},
        "An enrolled collector observed a connection to port 443 and an exact destination in active, provenance-bearing operator intelligence. Port 443 does not prove HTTPS or C2; protocol semantics are not inspected.",
        ["Stale or incorrect threat intelligence", "Shared hosting", "Authorized security lab traffic"],
        ["dst_ip", "dst_port", "source", "sensor", "host", "operator intelligence"],
        None,
    ),
]


def main():
    metadata = []
    for i, (
        slug,
        title,
        severity,
        technique,
        confidence,
        detection,
        explanation,
        fps,
        telemetry,
        aggregation,
    ) in enumerate(DEFINITIONS, 1):
        extension = {
            "slug": slug,
            "confidence": confidence,
            "required_telemetry": telemetry,
            "validation": "synthetic-fixtures",
            "explanation": explanation,
        }
        if aggregation:
            extension["aggregate"] = aggregation
        rule = {
            "title": title,
            "id": str(UUID(int=i)),
            "status": "experimental",
            "description": explanation,
            "author": "SentinelForge contributors",
            "date": "2026-11-15",
            "logsource": {"category": "normalized", "product": "sentinelforge"},
            "detection": detection,
            "level": severity,
            "tags": [f"attack.{technique.lower()}"],
            "falsepositives": fps,
            "x-sentinelforge": extension,
        }
        (ROOT / "rules" / f"{slug}.yml").write_text(yaml.safe_dump(rule, sort_keys=False))
        metadata.append({"slug": slug, "id": rule["id"], "technique": technique})

    def synthetic(kind="process", **kwargs):
        return {
            "source": "synthetic",
            "sensor": "fixture",
            "payload": {"timestamp": "2026-11-15T09:00:00Z", "host": "lab-01", "kind": kind, **kwargs},
        }

    ssh = [
        {
            "source": "linux_auth",
            "sensor": "auth-01",
            "payload": f"2026-11-15T09:00:0{i}Z edge-01 sshd[120{i}]: Failed password for analyst from 192.0.2.45 port 5100{i} ssh2",
        }
        for i in range(5)
    ]
    ps = {
        "source": "sysmon",
        "sensor": "sysmon-01",
        "payload": {
            "EventID": 1,
            "UtcTime": "2026-11-15 09:02:00",
            "Computer": "workstation-07",
            "User": "forge\\morgan",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGQAZQBtAG8A",
            "RecordID": "1001",
        },
    }
    shell = {
        "source": "auditd",
        "sensor": "audit-01",
        "host": "edge-01",
        "payload": 'type=SYSCALL msg=audit(1794733380.123:800): success=yes uid=1001 auid=1001 euid=1001 exe="/bin/bash"\n'
        'type=EXECVE msg=audit(1794733380.123:800): argc=3 a0="bash" a1="-c" a2="echo demo >/dev/tcp/192.0.2.9/4444"',
    }
    task = synthetic(
        process="C:\\Windows\\System32\\schtasks.exe",
        command="schtasks /create /tn LabTask /tr notepad.exe /sc onlogon",
        host="workstation-07",
        user="forge\\morgan",
    )
    account = synthetic(
        process="/usr/sbin/useradd", command="useradd -o -u 0 lab-admin", host="edge-01", user="analyst"
    )
    sudo = {
        "source": "linux_auth",
        "sensor": "auth-01",
        "payload": "2026-11-15T09:04:00Z edge-01 sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/bash",
    }
    zeek = {
        "source": "zeek",
        "sensor": "zeek-01",
        "host": "workstation-07",
        "payload": {
            "ts": 1794733500,
            "uid": "Cdemo01",
            "id.orig_h": "10.0.0.7",
            "id.resp_h": "1.1.1.1",
            "id.resp_p": 4444,
            "proto": "tcp",
            "orig_bytes": 620,
        },
    }
    positives = [ssh, [ps], [shell], [task], [account], [sudo], [zeek]]
    negatives = [
        ssh[:4],
        [synthetic(process="C:\\Windows\\powershell.exe", command="powershell -File inventory.ps1")],
        [synthetic(process="/bin/bash", command="bash -c uptime")],
        [synthetic(process="C:\\Windows\\schtasks.exe", command="schtasks /query")],
        [synthetic(process="/usr/sbin/useradd", command="useradd -u 1002 developer")],
        [{**sudo, "payload": sudo["payload"].replace("COMMAND=/bin/bash", "COMMAND=/usr/bin/id")}],
        [{**zeek, "payload": {**zeek["payload"], "id.resp_p": 443}}],
    ]
    tests = [{**m, "positive": p, "negative": n} for m, p, n in zip(metadata, positives, negatives)]
    (ROOT / "data" / "rule-fixtures.json").write_text(json.dumps(tests, indent=2) + "\n")
    scenarios = []
    for test in tests:
        for label, key in [(True, "positive"), (False, "negative")]:
            scenarios.append(
                {
                    "id": test["slug"] + "-" + key,
                    "suspicious": label,
                    "events": test[key],
                    "reason": "Rule contract fixture",
                }
            )
    scenarios += [
        {
            "id": "authorized-encoded-admin",
            "suspicious": False,
            "events": [ps],
            "reason": "Authorized encoded PowerShell produces a known false positive",
        },
        {
            "id": "authorized-task-maintenance",
            "suspicious": False,
            "events": [task],
            "reason": "Approved task creation produces a known false positive",
        },
        {
            "id": "powershell-file-evasion",
            "suspicious": True,
            "events": [
                synthetic(process="C:\\Windows\\powershell.exe", command="powershell -File untrusted.ps1")
            ],
            "reason": "Malicious file execution without monitored arguments is outside coverage",
        },
        {
            "id": "https-c2-blindspot",
            "suspicious": True,
            "events": [{**zeek, "payload": {**zeek["payload"], "id.resp_p": 443}}],
            "reason": "HTTPS C2 is not detected by the uncommon-port heuristic",
        },
    ]
    (ROOT / "data" / "evaluation.json").write_text(json.dumps(scenarios, indent=2) + "\n")
    demo = [event for events in positives for event in events]
    demo += [n[0] for n in negatives[1:]]
    demo += [
        {
            "source": "wazuh",
            "sensor": "wazuh-manager",
            "payload": {
                "id": "demo-wazuh-01",
                "timestamp": "2026-11-15T09:06:00Z",
                "agent": {"name": "db-02"},
                "decoder": {"name": "sshd"},
                "rule": {"id": "5715", "groups": ["authentication_success"]},
                "full_log": "sshd: Accepted publickey for deploy from 192.0.2.50 port 52120 ssh2",
            },
        }
    ]
    (ROOT / "data" / "demo.json").write_text(json.dumps({"events": demo}, indent=2) + "\n")


if __name__ == "__main__":
    main()
