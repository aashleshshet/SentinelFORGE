"""Regression contracts from useradd getopt and sudo log/executable semantics."""

from copy import deepcopy

import pytest
from sentinelforge.linux_evidence import sudo_shell_command
from sentinelforge.normalize import normalize
from sentinelforge.process_evidence import uid_zero_argument
from sentinelforge.schemas import Envelope


@pytest.mark.parametrize(
    "command,expected",
    [
        ("useradd -ou0 analyst", True),
        ("useradd -mou 000 analyst", True),
        ("useradd -u 1001 --uid=0 analyst", True),
        ("useradd -u 0 -u 1001 analyst", False),
        ("useradd -ou0 --uid 1001 analyst", False),
        ("useradd analyst -ou0", True),
        ("useradd -u0 -- -u1001", True),
        ("useradd -- -ou0", False),
        ('useradd -oc "-u 0" analyst', False),
        ("useradd -c-u0 analyst", False),
        ("useradd --comment=-u0 analyst", False),
        ("useradd -oc-u0 -u1001 analyst", False),
        ("useradd -oc-u1001 -u0 analyst", True),
        ("useradd -u0 --shell /bin/sh analyst", True),
        ("useradd -u0 -s", False),
        ("useradd -u0 --uid= analyst", False),
        ("useradd -u invalid -u0 analyst", False),
        ("useradd -u0 --unsupported analyst", False),
        ("useradd -Du0", False),
        ("useradd --defaults -u0", False),
        ("useradd -hu0", False),
        ("useradd -u0 --help", False),
        ("useradd -ou0001 analyst", False),
        ("useradd -ou-1 analyst", False),
        ("", False),
        (None, False),
    ],
)
def test_effective_useradd_uid(command, expected):
    event = {"kind": "process", "process": "/usr/sbin/useradd", "command": command}
    before = deepcopy(event)
    assert uid_zero_argument(event) is expected
    assert event == before


def test_linux_executable_identity_is_case_sensitive():
    event = {"kind": "process", "process": "/usr/sbin/USERADD", "command": "USERADD -u0 analyst"}
    assert not uid_zero_argument(event)


def sudo_event(command="/bin/bash", *, reason="", metadata="TTY=pts/0 ; PWD=/home/analyst ; "):
    line = f"2026-11-15T09:04:00Z edge-01 sudo[42]: analyst : {reason}{metadata}USER=root ; COMMAND={command}"
    return normalize(Envelope(source="linux_auth", sensor="test", payload=line)).model_dump()


@pytest.mark.parametrize(
    "command,expected",
    [
        ("/bin/bash", True),
        ("/usr/bin/bash -c id", True),
        ("/bin/sh -i", True),
        ("/usr/bin/sh", True),
        ("/bin/zsh", True),
        ("/usr/bin/zsh -l", True),
        ('"/bin/bash" -l', True),
        ("/usr/bin/printf /bin/bash", False),
        ("/bin/bash-backup", False),
        ("/bin/bash/file", False),
        ("/bin/BASH", False),
        ("/usr/bin/env /bin/bash", False),
        ('/usr/bin/printf "command not allowed /bin/bash"', False),
        ('/bin/bash "unterminated', False),
        ("/bin/bash " + "x " * 256, False),
    ],
)
def test_sudo_matches_executable_not_arguments(command, expected):
    event = sudo_event(command)
    before = deepcopy(event)
    assert event["outcome"] == "success"
    assert event["fields"]["sudo_authorization"] == "accepted"
    assert sudo_shell_command(event) is expected
    assert event == before


@pytest.mark.parametrize(
    "reason,outcome,authorization",
    [
        ("command not allowed", "failure", "denied"),
        ("user NOT in sudoers", "failure", "denied"),
        ("user NOT authorized on host", "failure", "denied"),
        ("3 incorrect password attempts", "failure", "denied"),
        ("1 incorrect password attempt", "failure", "denied"),
        ("a password is required", "failure", "denied"),
        (
            "sorry, you are not allowed to set the following environment variables: DEMO",
            "failure",
            "denied",
        ),
        ("unrecognized policy error", "unknown", "unknown"),
    ],
)
def test_sudo_denials_and_unknown_reasons_are_not_granted(reason, outcome, authorization):
    event = sudo_event(reason=reason + " ; ")
    assert event["outcome"] == outcome
    assert event["fields"]["sudo_authorization"] == authorization
    assert not sudo_shell_command(event)


def test_sudo_metadata_and_command_text_do_not_become_denial_reasons():
    event = sudo_event('/bin/bash -c "printf command-not-allowed"', metadata="PWD=/root ; ")
    assert sudo_shell_command(event)
    event = sudo_event("/bin/bash", metadata="")
    assert sudo_shell_command(event)


@pytest.mark.parametrize(
    "updates",
    [
        {"kind": "process"},
        {"process": "/bin/sudo"},
        {"outcome": "unknown"},
        {"outcome": "failure"},
        {"fields": {"target_user": "analyst", "sf_sudo_shell": True}},
        {"fields": None},
        {"command": None},
        {"command": ""},
        {"command": "/bin/bash " + "x" * 16384},
    ],
)
def test_sudo_shell_requires_observed_grant_and_root_target(updates):
    assert not sudo_shell_command(sudo_event() | updates)


def test_wazuh_preserves_denied_sudo_authorization():
    payload = {
        "agent": {"name": "edge-01"},
        "timestamp": "2026-11-15T09:04:00Z",
        "decoder": {"name": "sudo"},
        "full_log": (
            "sudo: analyst : command not allowed ; TTY=pts/0 ; PWD=/home/analyst ; "
            "USER=root ; COMMAND=/bin/bash"
        ),
    }
    event = normalize(Envelope(source="wazuh", sensor="test", payload=payload)).model_dump()
    assert event["source"] == "wazuh"
    assert event["outcome"] == "failure"
    assert event["fields"]["sudo_authorization"] == "denied"
    assert not sudo_shell_command(event)
