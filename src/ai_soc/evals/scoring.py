"""Scores one triage result against one answer-key case. No API calls here."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ai_soc.agent.verdict import Verdict


@dataclass
class Case:
    id: str
    alert_id: str
    fixture_dir: str | None
    verdict_in: list[str]
    techniques_include: list[str]
    evidence_any_of: list[str]

    @classmethod
    def load(cls, path: str | Path) -> "Case":
        raw: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        expect = raw.get("expect", {})
        return cls(
            id=raw["id"],
            alert_id=str(raw["alert_id"]),
            fixture_dir=raw.get("fixture_dir"),
            verdict_in=list(expect.get("verdict_in", [])),
            techniques_include=list(expect.get("techniques_include", [])),
            evidence_any_of=[str(x) for x in expect.get("evidence_any_of", [])],
        )


@dataclass
class Score:
    case_id: str
    checks: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(self.checks.values())


def score(case: Case, verdict: Verdict, seen_event_ids: set[str]) -> Score:
    s = Score(case_id=case.id)

    s.checks["verdict"] = verdict.verdict in case.verdict_in
    if not s.checks["verdict"]:
        s.notes.append(f"verdict '{verdict.verdict}' not in {case.verdict_in}")

    techniques = set(verdict.attack_techniques)
    missing = [t for t in case.techniques_include if t not in techniques]
    s.checks["techniques"] = not missing
    if missing:
        s.notes.append(f"missing ATT&CK techniques {missing}; got {sorted(techniques)}")

    cited = {e.event_id for e in verdict.evidence}
    s.checks["key_evidence"] = not case.evidence_any_of or bool(cited & set(case.evidence_any_of))
    if not s.checks["key_evidence"]:
        s.notes.append(f"cited {sorted(cited)}, none of the key events {case.evidence_any_of}")

    # The agent loop already rejects unseen ids; this re-check guards against loop regressions.
    unseen = cited - seen_event_ids
    s.checks["evidence_grounded"] = not unseen
    if unseen:
        s.notes.append(f"cited event ids never returned by tools: {sorted(unseen)}")

    return s
