"""Source-led command contracts; command strings are never executed."""

from copy import deepcopy

import pytest
from conftest import headers
from sentinelforge.process_evidence import process_evidence, scheduled_task_create, tokens


def powershell(command, image=r"C:\Windows\pwsh.exe"):
    return {
        "kind": "process",
        "process": image,
        "command": command,
        "parent": r"C:\Office\WINWORD.EXE",
        "fields": {},
    }


@pytest.mark.parametrize("flag", ["-exec", "-executionp", "-EP", "-window", "-windows"])
def test_supported_powershell_prefixes(flag):
    value = "Hidden" if flag.casefold().startswith("-w") else "Bypass"
    event = powershell(f'pwsh.exe {flag} {value} -File "C:\\Job Data\\daily.ps1"')
    assert process_evidence(event)["powershell_file_suspicious"]


@pytest.mark.parametrize(
    "command",
    [
        "pwsh -CustomPipeName -enc -Command Get-Date",
        "pwsh -ConfigurationName -enc -Command Get-Date",
        'pwsh -CustomPipeName "" -Command Get-Date -enc AAAA',
        "pwsh script.ps1 -enc AAAA",
        "pwsh -File script.ps1 -EncodedCommand AAAA",
        "pwsh -CommandWithArgs Get-Date -enc AAAA",
        "pwsh -CommandWithArgs Write-Output FromBase64String",
        "pwsh -ExecutionPolicy Bypass /NoProfile -Command Get-Date",
        "pwsh -unknown -enc AAAA",
        "pwsh -Help -enc AAAA",
        "pwsh -Version -enc AAAA",
        "pwsh -ExecutionPolicy -enc AAAA",
        "pwsh -WindowStyle -enc AAAA",
        "pwsh -InputFormat invalid -ExecutionPolicy Bypass -File demo.ps1",
    ],
)
def test_values_script_arguments_and_terminal_modes_are_not_engine_flags(command):
    result = process_evidence(powershell(command))
    assert not result["powershell_encoded"]
    assert not result["powershell_file_suspicious"]


@pytest.mark.parametrize(
    "command,expected",
    [
        ("pwsh -window Hidden invoice.ps1", True),
        ("pwsh -exec Bypass -exec Restricted -File invoice.ps1", False),
        ("pwsh -exec Restricted -exec Bypass -File invoice.ps1", True),
        ("pwsh -window Hidden -w Normal -File invoice.ps1", False),
        ('pwsh -CustomPipeName "" -exec Bypass -File invoice.ps1', True),
        ("pwsh -CustomPipeName -File invoice.ps1", False),
    ],
)
def test_effective_option_values_and_implicit_file(command, expected):
    assert process_evidence(powershell(command))["powershell_file_suspicious"] is expected


@pytest.mark.parametrize("prefix", ["-", "--", "/"])
def test_powershell_native_option_introducers(prefix):
    event = powershell(f"pwsh {prefix}NoProfile {prefix}EncodedCommand AAAA")
    assert process_evidence(event)["powershell_encoded"]


def test_powershell_absolute_executable_and_valid_format():
    event = powershell("/opt/powershell/pwsh -InputFormat XML -enc AAAA", "/opt/powershell/pwsh")
    assert process_evidence(event)["powershell_encoded"]


def test_windows_powershell_positional_command_is_not_assumed_to_be_file():
    event = powershell("powershell -exec Bypass invoice.ps1", r"C:\Windows\powershell.exe")
    assert not process_evidence(event)["powershell_file_suspicious"]


def test_empty_quotes_preserve_argument_positions_and_bounds():
    assert tokens('pwsh -CustomPipeName "" -NoProfile') == ["pwsh", "-CustomPipeName", "", "-NoProfile"]
    assert tokens('pwsh -CustomPipeName "unfinished') is None
    assert tokens("arg " * 257) is None
    assert tokens("a" * 16385) is None


@pytest.mark.parametrize(
    "command,expected",
    [
        ('schtasks.exe /Create /TN Daily /TR "tool.exe" /SC DAILY', True),
        ('"C:\\Windows\\System32\\schtasks.exe" /CREATE /TN Job', True),
        ('schtasks.exe /Change /TN Job /TR "tool.exe /create"', False),
        ('schtasks.exe /Query /TN "/create"', False),
        ("schtasks.exe /createish", False),
        ('schtasks.exe /Create /TN "truncated', False),
        ("schtasks.exe", False),
    ],
)
def test_scheduled_task_operation(command, expected):
    event = {"kind": "process", "process": r"C:\Windows\schtasks.exe", "command": command}
    assert scheduled_task_create(event) is expected
    event["process"] = r"C:\Windows\echo.exe"
    assert not scheduled_task_create(event)


def test_derived_action_flags_cannot_be_supplied_by_collector(client):
    event = {
        "source": "synthetic",
        "sensor": "argument-contract",
        "payload": {
            "timestamp": "2026-11-16T09:00:00Z",
            "host": "argument-lab",
            "kind": "process",
            "process": r"C:\Windows\schtasks.exe",
            "command": 'schtasks /Change /TN Job /TR "tool.exe /create"',
            "fields": {"sf_scheduled_task_create": True, "sf_sudo_shell": True},
        },
    }
    before = deepcopy(event)
    response = client.post("/api/ingest", json={"events": [event]}, headers=headers("collector"))
    assert response.status_code == 200
    assert response.json()["accepted"] == 1
    assert response.json()["alerts_created"] == 0
    row = client.get("/api/events", headers=headers()).json()["items"][0]
    detail = client.get("/api/events/" + row["id"], headers=headers()).json()
    assert detail["raw"]["payload"] == before["payload"]
    assert detail["data"]["fields"] == before["payload"]["fields"]
