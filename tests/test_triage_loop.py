"""Tests the agent loop with a scripted fake Claude, so no API key or money is needed.
The SIEM side is real: the in-process siem-mcp server over the fixture data."""

from types import SimpleNamespace as NS

import pytest
from mcp import Client

from ai_soc.agent.triage import TriageError, triage
from ai_soc.config import Settings
from ai_soc.evals.scoring import Case, score
from ai_soc.mcp_servers.siem_server import build_server
from ai_soc.siem.backends import FixtureBackend

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _tool_use(id_, name, input_):
    return NS(type="tool_use", id=id_, name=name, input=input_)


def _reply(*blocks, stop="tool_use"):
    return NS(stop_reason=stop, content=list(blocks), usage=NS(input_tokens=100, output_tokens=20))


GOOD_VERDICT = {
    "verdict": "malicious",
    "confidence": 0.8,
    "attack_techniques": ["T1059.001"],
    "summary": "PowerShell ran a base64-encoded command spawned from another PowerShell session.",
    "evidence": [{"event_id": "ev-0004", "why": "encoded PowerShell command line"}],
    "next_steps": ["Decode the command", "Check who launched the parent PowerShell"],
}


class FakeLLM:
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []
        self.beta = NS(messages=NS(create=self._create))

    def _create(self, **kwargs):
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})  # snapshot: the loop mutates the list
        return self.replies.pop(0)


def settings(**overrides):
    base = Settings.from_env()
    return base.__class__(**{**base.__dict__, "max_agent_turns": 6, **overrides})


async def test_full_loop_rejects_ungrounded_evidence_then_accepts():
    bad = {**GOOD_VERDICT, "evidence": [{"event_id": "ev-9999", "why": "made up"}]}
    llm = FakeLLM(
        [
            _reply(_tool_use("t1", "get_alert", {"alert_id": "1764065109.4471"})),
            _reply(
                _tool_use(
                    "t2",
                    "search_events",
                    {"host": "WS01", "start": "2026-11-25T09:50:00Z", "end": "2026-11-25T10:20:00Z"},
                )
            ),
            _reply(_tool_use("t3", "submit_verdict", bad)),
            _reply(_tool_use("t4", "submit_verdict", GOOD_VERDICT)),
        ]
    )
    async with Client(build_server(FixtureBackend("fixtures/T1059_001"))) as siem:
        result = await triage("1764065109.4471", siem, llm, settings())

    assert result.verdict.verdict == "malicious"
    assert result.turns == 4
    assert {"ev-0003", "ev-0004", "1764065109.4471"} <= result.seen_event_ids
    rejected = [s for s in result.steps if s["tool"] == "submit_verdict" and not s["accepted"]]
    assert rejected and "ev-9999" in rejected[0]["problem"]

    # The rejection message actually reached the model as an error tool_result.
    last_user = llm.calls[-1]["messages"][-1]
    assert last_user["content"][0]["is_error"] is True

    # Request shape: our tools plus submit_verdict, fallback enabled, no forced tool_choice.
    first = llm.calls[0]
    assert sorted(t["name"] for t in first["tools"]) == ["get_alert", "search_events", "submit_verdict"]
    assert first["fallbacks"] == "default" and "tool_choice" not in first

    s = score(Case.load("evals/cases/T1059_001.yaml"), result.verdict, result.seen_event_ids)
    assert s.passed, s.notes


async def test_refusal_stops_with_error():
    llm = FakeLLM([NS(stop_reason="refusal", content=[], usage=NS(input_tokens=1, output_tokens=0), stop_details="cyber")])
    async with Client(build_server(FixtureBackend("fixtures/T1059_001"))) as siem:
        with pytest.raises(TriageError, match="declined"):
            await triage("1764065109.4471", siem, llm, settings())


async def test_gives_up_after_max_turns():
    llm = FakeLLM([_reply(NS(type="text", text="thinking out loud"), stop="end_turn")] * 3)
    async with Client(build_server(FixtureBackend("fixtures/T1059_001"))) as siem:
        with pytest.raises(TriageError, match="No valid verdict"):
            await triage("1764065109.4471", siem, llm, settings(max_agent_turns=3))


def test_scoring_fails_benign_verdict():
    case = Case.load("evals/cases/T1059_001.yaml")
    from ai_soc.agent.verdict import Verdict

    v = Verdict.model_validate({**GOOD_VERDICT, "verdict": "benign", "attack_techniques": []})
    s = score(case, v, {"ev-0004"})
    assert not s.passed
    assert not s.checks["verdict"] and not s.checks["techniques"]
