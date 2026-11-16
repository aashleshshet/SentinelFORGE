import pytest
from conftest import headers
from sentinelforge.normalize import normalize
from sentinelforge.schemas import Envelope


@pytest.mark.parametrize(
    "source,payload",
    [("wazuh", {"agent": []}), ("sysmon", {"Event": None}), ("auditd", {"exe": []}), ("zeek", {})],
)
def test_malformed_adapter_shape_is_rejected_not_500(client, source, payload):
    response = client.post(
        "/api/ingest",
        json={"events": [{"source": source, "sensor": "test", "host": "test", "payload": payload}]},
        headers=headers(),
    )
    assert response.status_code == 200
    assert response.json()["rejected"] == 1
    assert client.get("/api/stats", headers=headers()).json()["events"] == 0


def test_sysmon_network_and_wazuh_windows_mapping():
    sysmon = {
        "Event": {
            "System": {"EventID": 3, "Computer": "WIN-01"},
            "EventData": {
                "UtcTime": "2026-11-15 09:00:00",
                "SourceIp": "10.0.0.1",
                "DestinationIp": "1.1.1.1",
                "DestinationPort": "443",
            },
        }
    }
    event = normalize(Envelope(source="sysmon", sensor="s", payload=sysmon))
    assert event.kind == "network" and event.dst_port == 443 and event.host == "win-01"
    wazuh = {
        "agent": {"name": "WIN-01"},
        "timestamp": "2026-11-15T09:00:00Z",
        "data": {
            "win": {
                "system": {"eventID": "1"},
                "eventdata": {
                    "image": "C:\\powershell.exe",
                    "commandLine": "powershell -enc AAA",
                    "user": "CORP\\Alice",
                },
            }
        },
    }
    event = normalize(Envelope(source="wazuh", sensor="w", payload=wazuh))
    assert event.source == "wazuh" and event.kind == "process" and event.user == "corp\\alice"


def test_nonpublic_destination_not_flagged(client):
    event = {
        "source": "zeek",
        "sensor": "test",
        "host": "test",
        "payload": {"ts": 1794733200, "id.resp_h": "10.0.0.2", "id.resp_p": 4444},
    }
    result = client.post("/api/ingest", json={"events": [event]}, headers=headers()).json()
    assert result["accepted"] == 1 and result["alerts_created"] == 0


def test_source_attribution_cannot_be_overridden(client):
    event = {
        "source": "synthetic",
        "sensor": "trusted-envelope",
        "payload": {
            "source": "sysmon",
            "sensor": "fake",
            "host": "test",
            "timestamp": "2026-11-15T09:00:00Z",
            "kind": "other",
        },
    }
    client.post("/api/ingest", json={"events": [event]}, headers=headers())
    stored = client.get("/api/events", headers=headers()).json()["items"][0]
    assert stored["source"] == "synthetic" and stored["sensor"] == "trusted-envelope"


def test_sysmon_original_filename_observation_is_not_script_hash():
    event = normalize(
        Envelope(
            source="sysmon",
            sensor="s",
            payload={
                "EventID": 1,
                "Computer": "win-01",
                "UtcTime": "2026-11-15 09:00:00",
                "Image": r"C:\Temp\renamed.exe",
                "OriginalFileName": "PowerShell.EXE",
                "CommandLine": "renamed.exe -File job.ps1",
                "Hashes": "SHA256=" + "a" * 64,
            },
        )
    )
    assert event.fields["original_file_name"] == "PowerShell.EXE"
    assert "script_sha256" not in event.fields
