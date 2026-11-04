# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""Markdown / text rendering of an RCA result."""
from __future__ import annotations

from typing import List, Optional

from .correlate import RCAResult
from .llm import LLMAnswer
from .topology import Topology


def _role(e, r: RCAResult) -> str:
    if r.best.culprit is not None and e.id == r.best.culprit.id:
        return "**CULPRIT**"
    if e.id == r.symptom.id:
        return "symptom (victim)"
    if any(p.id == e.id for p in r.precursors):
        return "precursor"
    if any(v.id == e.id for v in r.victims):
        return "victim"
    if any(v.id == e.id for v in r.recovery):
        return "recovery"
    return "context"


def to_markdown(r: RCAResult, topo: Topology, llm: Optional[LLMAnswer] = None) -> str:
    out: List[str] = [f"# Root-cause analysis for {r.symptom.system}: path fault at {r.symptom.timestamp:%Y-%m-%d %H:%M:%S}Z",
                      "",
                      f"**Root cause:** {r.best.title}  ",
                      f"**Culprit event:** `{r.best.culprit.id if r.best.culprit else '-'}`  ",
                      f"**Confidence:** {r.confidence:.0%} (share of the total hypothesis score)",
                      "",
                      "## I/O path",
                      f"- Initiator: {topo.label(r.initiator) if r.initiator else 'unknown'}",
                      f"- Target: {topo.label(r.target) if r.target else 'unknown'}"]
    for k, v in r.joined.items():
        out.append(f"- {k.replace('_', ' ')}: {' '.join(v) if v else 'not in topology'}")
    out += ["", "## Evidence timeline", "", "| Time (UTC) | Source | Event | Role | Id |", "|---|---|---|---|---|"]
    path_ids = {e.id for e in r.victims + r.recovery + r.precursors} | ({r.best.culprit.id} if r.best.culprit else set()) | {r.symptom.id}
    for e in sorted(r.retrieved, key=lambda e: e.ts):
        if e.id not in path_ids and not r.best.support.count(e):
            continue
        where = f"{e.system} {e.port or e.device or ''}".strip()
        out.append(f"| {e.timestamp:%H:%M:%S} | {e.source}: {where} | {e.event_type}: {e.message[:70]} | {_role(e, r)} | `{e.id}` |")
    out += ["", "## Alternatives considered", ""]
    for h in r.alternatives:
        reason = "; ".join(h.contradictions) or "lower score"
        out.append(f"- **{h.name}** (score {h.score:.1f}): {reason}")
    if llm is not None:
        out += ["", "## Local LLM explanation", ""]
        if llm.valid:
            out += [f"- Root cause: {llm.root_cause}", f"- Culprit: `{llm.culprit_event_id}`",
                    f"- Victims: {', '.join(f'`{v}`' for v in llm.victim_event_ids)}",
                    f"- Reasoning: {llm.reasoning}",
                    f"- Agrees with the evidence engine: {'yes' if llm.agrees_with_engine else 'NO - review manually'}"]
        else:
            out.append(f"- Rejected: {'; '.join(llm.problems)}")
    out += ["", f"_Retrieved {len(r.retrieved)} events; every cited id above is among them._"]
    return "\n".join(out) + "\n"
