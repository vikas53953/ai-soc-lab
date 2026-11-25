import pytest

from ai_soc.siem.backends import FixtureBackend, SiemError

FIX = "fixtures/T1059_001"


def test_get_alert_returns_normalized_alert():
    alert = FixtureBackend(FIX).get_alert("1764065109.4471")
    assert alert["event_id"] == "1764065109.4471"
    assert alert["host"] == "WS01"
    assert alert["rule"]["id"] == "100200"
    assert alert["rule"]["mitre"] == ["T1059.001"]
    assert " -e " in alert["fields"]["commandLine"]


def test_unknown_alert_raises():
    with pytest.raises(SiemError):
        FixtureBackend(FIX).get_alert("nope")


def test_search_filters_by_host_and_window():
    events = FixtureBackend(FIX).search_events("WS01", "2026-11-25T10:04:00Z", "2026-11-25T10:06:00Z")
    ids = [e["event_id"] for e in events]
    assert ids == ["ev-0003", "ev-0004", "ev-0005", "ev-0006"]  # WS02 event ev-0101 excluded


def test_search_contains_and_limit():
    backend = FixtureBackend(FIX)
    hits = backend.search_events("WS01", "2026-11-25T10:00:00Z", "2026-11-25T10:30:00Z", contains="conhost")
    assert [e["event_id"] for e in hits] == ["ev-0005"]
    assert len(backend.search_events("WS01", "2026-11-25T10:00:00Z", "2026-11-25T10:30:00Z", limit=2)) == 2
