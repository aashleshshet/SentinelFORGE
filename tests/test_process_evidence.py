"""Behavior contracts written before the bounded PowerShell parser implementation."""

import base64
from copy import deepcopy

import pytest
from sentinelforge.process_evidence import process_evidence


def process(command, **updates):
    return {
        "kind": "process",
        "process": r"C:\Windows\powershell.exe",
        "command": command,
        "parent": r"C:\Windows\explorer.exe",
        "fields": {},
        **updates,
    }


@pytest.mark.parametrize("flag", ["-e", "-en", "-enc", "-EncodedCommand", "-ENCODEDCOMMAND"])
def test_encoded_argument_forms(flag):
    encoded = base64.b64encode("Write-Output demo".encode("utf-16-le")).decode()
    result = process_evidence(process(f'powershell.exe {flag} "{encoded}"'))
    assert result["powershell_encoded"]
    assert not result["powershell_file_suspicious"]
    assert any("UTF-16LE" in detail for detail in result["details"])


def test_encoded_payload_is_bounded_and_never_executed(tmp_path):
    marker = tmp_path / "must-not-exist"
    script = f"Set-Content {marker} executed"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    assert process_evidence(process(f"powershell -enc {encoded}"))["powershell_encoded"]
    assert not marker.exists()
    for command in ["powershell -enc", "powershell -enc !!!", "powershell -enc " + "A" * 9000]:
        result = process_evidence(process(command))
        assert result["powershell_encoded"]
        assert result["details"]


@pytest.mark.parametrize(
    "command",
    [
        "powershell -File inventory.ps1",
        "powershell -f untrusted.ps1",
        "powershell -File inventory.ps1 -enc not-an-engine-option",
        "powershell -ExecutionPolicy Bypass -File install.ps1",
        "powershell -Command Write-Output routine",
    ],
)
def test_ordinary_files_and_script_arguments_are_not_malicious(command):
    result = process_evidence(process(command))
    assert not result["powershell_file_suspicious"]
    assert not result["powershell_encoded"]


@pytest.mark.parametrize("flag", ["-File", "-f", "-FiLe"])
def test_file_with_office_ancestry_and_evasion_context(flag):
    event = process(
        f'powershell -ExecutionPolicy Bypass {flag} "C:\\User Data\\invoice.ps1"',
        parent=r"C:\Program Files\Office\WINWORD.EXE",
    )
    result = process_evidence(event)
    assert result["powershell_file_suspicious"]
    assert any("Office" in detail for detail in result["details"])
    event["parent"] = r"C:\Windows\explorer.exe"
    assert not process_evidence(event)["powershell_file_suspicious"]
    event["parent"] = r"C:\Office\excel.exe"
    event["command"] = f"powershell {flag} invoice.ps1"
    assert not process_evidence(event)["powershell_file_suspicious"]


def test_file_hash_requires_observed_path_and_scoped_indicator():
    event = process(
        'powershell -File "C:\\Scripts\\job.ps1"',
        fields={"script_path": r"C:\Scripts\job.ps1", "script_sha256": "a" * 64},
    )
    indicator = {"id": "test-ioc", "kind": "script_sha256", "value": "a" * 64, "version": "test-v1"}
    assert process_evidence(event, indicator)["powershell_file_suspicious"]
    assert not process_evidence(event)["powershell_file_suspicious"]
    event["fields"]["script_path"] = r"C:\Scripts\different.ps1"
    assert not process_evidence(event, indicator)["powershell_file_suspicious"]


def test_renamed_binary_uses_original_filename_observation():
    event = process(
        "renamed.exe -WindowStyle Hidden -File payload.ps1",
        process=r"C:\Temp\renamed.exe",
        parent=r"C:\Office\OUTLOOK.EXE",
        fields={"original_file_name": "PowerShell.EXE"},
    )
    assert process_evidence(event)["powershell_file_suspicious"]
    event["fields"] = {}
    assert not process_evidence(event)["powershell_file_suspicious"]


def test_missing_truncated_quoted_fields_and_spoofed_flags_do_not_create_file_signal():
    for command in [None, "", "powershell -File", 'powershell -File "truncated', "powershell -File -"]:
        event = process(
            command, parent=r"C:\Office\WINWORD.EXE", fields={"sf_powershell_file_suspicious": True}
        )
        before = deepcopy(event)
        assert not process_evidence(event)["powershell_file_suspicious"]
        assert event == before
    assert not process_evidence(process("powershell -enc AA==", kind="other"))["powershell_encoded"]


@pytest.mark.parametrize(
    "command,expected",
    [
        ("useradd -u 0 service", True),
        ("useradd -u0 service", True),
        ("useradd --uid=0 service", True),
        ("useradd --uid 000 service", True),
        ("useradd -u 0001 service", False),
        ("useradd --uid 010 service", False),
        ('useradd --comment "-u 0" service', False),
        ("useradd -- -u0", False),
        ("useradd -u", False),
        ('useradd -u "0', False),
    ],
)
def test_uid_zero_argument_identity(command, expected):
    from sentinelforge.process_evidence import uid_zero_argument

    assert uid_zero_argument(process(command, process="/usr/sbin/useradd")) is expected


def test_uid_looking_comment_is_not_a_uid_option():
    from sentinelforge.process_evidence import uid_zero_argument

    assert not uid_zero_argument(process('useradd -c "-u0" service', process="/usr/sbin/useradd"))
