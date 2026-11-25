"""The verdict the triage agent must return, and the tool it uses to return it."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class Evidence(BaseModel):
    event_id: str = Field(min_length=1)
    why: str = Field(min_length=1)


class Verdict(BaseModel):
    verdict: Literal["malicious", "suspicious", "benign"]
    confidence: float = Field(ge=0.0, le=1.0)
    attack_techniques: list[str]
    summary: str = Field(min_length=1)
    evidence: list[Evidence] = Field(min_length=1)
    next_steps: list[str]

    @field_validator("attack_techniques")
    @classmethod
    def _valid_attack_ids(cls, ids: list[str]) -> list[str]:
        bad = [i for i in ids if not ATTACK_ID.match(i)]
        if bad:
            raise ValueError(f"not MITRE ATT&CK technique ids: {bad} (expected like T1059 or T1059.001)")
        return ids


SUBMIT_VERDICT_TOOL = {
    "name": "submit_verdict",
    "description": (
        "Submit your final triage verdict. Call this exactly once, after investigating. "
        "Every evidence item must cite an event_id you actually received from get_alert or search_events."
    ),
    "strict": True,
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["verdict", "confidence", "attack_techniques", "summary", "evidence", "next_steps"],
        "properties": {
            "verdict": {"type": "string", "enum": ["malicious", "suspicious", "benign"]},
            "confidence": {"type": "number", "description": "0.0 to 1.0"},
            "attack_techniques": {
                "type": "array",
                "items": {"type": "string"},
                "description": "MITRE ATT&CK technique ids, e.g. T1059.001. Empty if benign.",
            },
            "summary": {"type": "string", "description": "Two to four sentences for a SOC analyst."},
            "evidence": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["event_id", "why"],
                    "properties": {"event_id": {"type": "string"}, "why": {"type": "string"}},
                },
            },
            "next_steps": {"type": "array", "items": {"type": "string"}},
        },
    },
}
