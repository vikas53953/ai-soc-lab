"""Runs every answer-key case in evals/cases through the triage agent and scores it.

    run-evals                      (all cases)
    run-evals --case evals/cases/T1059_001.yaml

Writes results/eval-<UTC time>.json and prints one line per case. Each case makes real
Claude API calls, so each run costs money.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ai_soc.agent.triage import TriageError, run_one
from ai_soc.config import Settings
from ai_soc.evals.scoring import Case, score


async def run_case(case: Case, settings: Settings) -> dict:
    if settings.siem_backend == "fixture" and case.fixture_dir:
        os.environ["FIXTURE_DIR"] = case.fixture_dir  # the SIEM server subprocess reads this
        settings = replace(settings, fixture_dir=case.fixture_dir)
    try:
        result = await run_one(case.alert_id, settings)
    except TriageError as exc:
        return {"case": case.id, "passed": False, "error": str(exc)}
    s = score(case, result.verdict, result.seen_event_ids)
    return {"case": case.id, "passed": s.passed, "checks": s.checks, "notes": s.notes, "result": result.to_dict()}


async def run_all(paths: list[Path], settings: Settings) -> list[dict]:
    return [await run_case(Case.load(p), settings) for p in paths]


def main() -> None:
    parser = argparse.ArgumentParser(description="Score the triage agent against labeled cases")
    parser.add_argument("--case", action="append", help="path to one case YAML (repeatable)")
    args = parser.parse_args()

    paths = [Path(p) for p in args.case] if args.case else sorted(Path("evals/cases").glob("*.yaml"))
    if not paths:
        print("No cases found in evals/cases", file=sys.stderr)
        sys.exit(2)

    settings = Settings.from_env()
    rows = asyncio.run(run_all(paths, settings))

    out_dir = Path("results")
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = out_dir / f"eval-{stamp}.json"
    out.write_text(json.dumps({"model": settings.claude_model, "backend": settings.siem_backend, "cases": rows}, indent=2))

    passed = sum(r["passed"] for r in rows)
    for r in rows:
        status = "PASS" if r["passed"] else "FAIL"
        detail = r.get("error") or "; ".join(r.get("notes", [])) or "all checks passed"
        usage = r.get("result", {}).get("usage", {})
        print(f"{status}  {r['case']}  ({usage.get('input_tokens', 0)} in / {usage.get('output_tokens', 0)} out tokens)  {detail}")
    print(f"\n{passed}/{len(rows)} cases passed. Details: {out}")
    sys.exit(0 if passed == len(rows) else 1)


if __name__ == "__main__":
    main()
