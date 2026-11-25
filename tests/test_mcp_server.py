import json
import os

import pytest
from mcp import Client

from ai_soc.agent.triage import siem_server_params
from ai_soc.mcp_servers.siem_server import build_server
from ai_soc.siem.backends import FixtureBackend

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _payload(result):
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


async def test_lists_two_tools():
    async with Client(build_server(FixtureBackend("fixtures/T1059_001"))) as client:
        names = sorted(t.name for t in (await client.list_tools()).tools)
    assert names == ["get_alert", "search_events"]


async def test_get_alert_and_search():
    async with Client(build_server(FixtureBackend("fixtures/T1059_001"))) as client:
        alert = _payload(await client.call_tool("get_alert", {"alert_id": "1764065109.4471"}))
        found = _payload(
            await client.call_tool(
                "search_events",
                {"host": "WS01", "start": "2026-11-25T10:04:00Z", "end": "2026-11-25T10:06:00Z"},
            )
        )
    assert alert["rule"]["id"] == "100200"
    assert found["count"] == 4


async def test_window_over_24h_is_an_error():
    async with Client(build_server(FixtureBackend("fixtures/T1059_001"))) as client:
        result = await client.call_tool(
            "search_events", {"host": "WS01", "start": "2026-11-20T00:00:00Z", "end": "2026-11-25T00:00:00Z"}
        )
    assert result.is_error


async def test_real_stdio_subprocess_without_api_key(monkeypatch):
    """Starts the server the same way the agent does, and checks the API key is not passed to it."""
    monkeypatch.setenv("SIEM_BACKEND", "fixture")
    monkeypatch.setenv("FIXTURE_DIR", "fixtures/T1059_001")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-should-not-leak")
    params = siem_server_params()
    assert "ANTHROPIC_API_KEY" not in params.env
    assert params.env["FIXTURE_DIR"] == "fixtures/T1059_001"
    async with Client(params) as client:
        alert = _payload(await client.call_tool("get_alert", {"alert_id": "1764065109.4471"}))
    assert alert["host"] == "WS01"
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-test-should-not-leak"
