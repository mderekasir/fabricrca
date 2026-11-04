# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""Evidence-cited answer generation with a local LLM (paper Sec. III-C).

The model receives only the retrieved events (each with its id) and must
return JSON naming the culprit event id, victim event ids and a short root
cause.  The answer is then *checked*: every cited id must be one of the
retrieved events and the culprit must not come after its victims.  An answer
that fails the check is rejected and the deterministic result stands.

Uses Ollama's ``/api/chat`` with schema-constrained output via ``urllib`` -
no SDK required.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .correlate import RCAResult

SYSTEM = """You are a storage-network root-cause analyst.
You are given a host symptom and a list of retrieved events from the host, the Fibre Channel
switches and the storage array. Each event has an id in square brackets.
Rules:
- Base your answer ONLY on the listed events. Cite event ids exactly as given.
- The culprit is the earliest event on the I/O path that explains the later events.
- A failing switch-side optic or port shows up on the switch BEFORE the host and array.
- A failing host HBA shows up on the host with NO earlier switch-side alarm.
- If the evidence is insufficient, say so and set culprit_event_id to "".
Return JSON only."""

ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "root_cause": {"type": "string"},
        "culprit_event_id": {"type": "string"},
        "victim_event_ids": {"type": "array", "items": {"type": "string"}},
        "reasoning": {"type": "string"},
    },
    "required": ["root_cause", "culprit_event_id", "victim_event_ids", "reasoning"],
}


@dataclass
class LLMAnswer:
    root_cause: str
    culprit_event_id: str
    victim_event_ids: List[str]
    reasoning: str
    valid: bool = True
    problems: List[str] = field(default_factory=list)
    agrees_with_engine: Optional[bool] = None


def build_prompt(result: RCAResult) -> str:
    lines = [f"SYMPTOM: {result.symptom.short()}", "", "RETRIEVED EVENTS (time-ordered):"]
    lines += [e.short() for e in sorted(result.retrieved, key=lambda e: e.ts)]
    lines += ["", "Which event is the root cause of the symptom, and which events are its victims?"]
    return "\n".join(lines)


def verify(answer: Dict[str, Any], result: RCAResult) -> LLMAnswer:
    ids = {e.id: e for e in result.retrieved}
    a = LLMAnswer(str(answer.get("root_cause", "")), str(answer.get("culprit_event_id", "")),
                  [str(x) for x in answer.get("victim_event_ids", [])], str(answer.get("reasoning", "")))
    cited = ([a.culprit_event_id] if a.culprit_event_id else []) + a.victim_event_ids
    unknown = [c for c in cited if c not in ids]
    if unknown:
        a.problems.append(f"cites events that were not retrieved: {unknown}")
    if a.culprit_event_id in ids:
        c = ids[a.culprit_event_id]
        later = [v for v in a.victim_event_ids if v in ids and ids[v].ts + 2.0 < c.ts]
        if later:
            a.problems.append(f"culprit occurs after its claimed victims {later}")
    a.valid = not a.problems
    if result.best.culprit is not None:
        a.agrees_with_engine = a.culprit_event_id == result.best.culprit.id
    return a


class OllamaExplainer:
    def __init__(self, model: str = "qwen2.5:7b", host: str = "http://localhost:11434", timeout: float = 180) -> None:
        self.model, self.host, self.timeout = model, host.rstrip("/"), timeout

    def ask(self, result: RCAResult) -> LLMAnswer:
        body = json.dumps({"model": self.model, "stream": False, "format": ANSWER_SCHEMA,
                           "options": {"temperature": 0},
                           "messages": [{"role": "system", "content": SYSTEM},
                                        {"role": "user", "content": build_prompt(result)}]}).encode()
        req = urllib.request.Request(f"{self.host}/api/chat", data=body, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                content = json.loads(resp.read())["message"]["content"]
            return verify(json.loads(content), result)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
            return LLMAnswer("", "", [], "", valid=False, problems=[f"local model unavailable: {exc}"])
