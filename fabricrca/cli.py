# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""Command line::

    fabricrca analyze examples/sfp_failure/case.json
    fabricrca analyze case.json --llm ollama --model qwen2.5:7b --markdown rca.md --json rca.json
    fabricrca events case.json            # show the normalised event stream

A *case file* lists the evidence sources (paths are relative to the case file)::

    {"year": 2026,
     "topology": "topology.json",
     "hosts":    [{"name": "dbhost1", "log": "host.log", "multipath_ll": "multipath_ll.txt",
                   "host_info": "host_info.json", "offset_s": 0}],
     "switches": [{"name": "edge-a", "log": "edge-a.log"}],
     "arrays":   [{"name": "ARRAY-01", "log": "array.log"}],
     "switch_rules": null, "array_rules": null}

``offset_s`` corrects a known clock skew for a source (seconds added to its timestamps).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .correlate import analyze, find_symptoms
from .index import EventIndex
from .llm import OllamaExplainer
from .parsers import (DEFAULT_ARRAY_RULES, DEFAULT_SWITCH_RULES, HostContext, load_rules, parse_host_log,
                      parse_rule_log)
from .report import to_markdown
from .schema import Event
from .topology import Topology


def _read(base: str, rel: Optional[str]) -> Optional[str]:
    if not rel:
        return None
    with open(os.path.join(base, rel), encoding="utf-8") as fh:
        return fh.read()


def load_case(path: str) -> Tuple[List[Event], Topology, Dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        case = json.load(fh)
    base = os.path.dirname(os.path.abspath(path))
    year = case.get("year")
    topo = Topology.from_file(os.path.join(base, case["topology"]) if case.get("topology") else None)
    events: List[Event] = []
    for h in case.get("hosts", []):
        info = json.loads(_read(base, h.get("host_info")) or "{}")
        ctx = HostContext.load(h["name"], _read(base, h.get("multipath_ll")), info)
        events += parse_host_log((_read(base, h["log"]) or "").splitlines(), ctx, year, h.get("offset_s", 0.0))
    sw_rules = load_rules(os.path.join(base, case["switch_rules"]) if case.get("switch_rules") else None,
                          DEFAULT_SWITCH_RULES)
    ar_rules = load_rules(os.path.join(base, case["array_rules"]) if case.get("array_rules") else None,
                          DEFAULT_ARRAY_RULES)
    for s in case.get("switches", []):
        events += parse_rule_log((_read(base, s["log"]) or "").splitlines(), "switch", s["name"], sw_rules,
                                 year, s.get("offset_s", 0.0))
    for a in case.get("arrays", []):
        events += parse_rule_log((_read(base, a["log"]) or "").splitlines(), "array", a["name"], ar_rules,
                                 year, a.get("offset_s", 0.0))
    topo.enrich(events)
    return sorted(events, key=lambda e: e.ts), topo, case


def cmd_events(a) -> int:
    events, _topo, _ = load_case(a.case)
    for e in events:
        print(e.short() + (f"  wwns={','.join(e.wwns)}" if e.wwns else ""))
    return 0


def cmd_analyze(a) -> int:
    events, topo, _ = load_case(a.case)
    index = EventIndex(events)
    if a.retriever == "llamaindex":  # pragma: no cover
        from .index import LlamaIndexRetriever
        index_search = LlamaIndexRetriever(events, a.embed_model, a.ollama_host)
        index.search = index_search.search  # type: ignore[assignment]
    symptoms = find_symptoms(events)
    if a.symptom:
        symptoms = [e for e in events if e.id == a.symptom]
    if not symptoms:
        print("no host path-fault symptom found (use --symptom ID to pick an event)", file=sys.stderr)
        return 2
    if not a.all:
        symptoms = symptoms[:1]
    explainer = OllamaExplainer(a.model, a.ollama_host) if a.llm == "ollama" else None
    results = []
    md_parts = []
    for s in symptoms:
        r = analyze(s, index, topo, before=a.window, after=a.after, skew=a.skew)
        ans = explainer.ask(r) if explainer else None
        md_parts.append(to_markdown(r, topo, ans))
        d = r.to_dict()
        if ans is not None:
            d["llm"] = ans.__dict__
        results.append(d)
    md = "\n---\n\n".join(md_parts)
    print(md)
    if a.markdown:
        with open(a.markdown, "w", encoding="utf-8") as fh:
            fh.write(md)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(results if a.all else results[0], fh, indent=2, default=str)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="fabricrca", description="Correlate host multipath loss with fabric and array events")
    ap.add_argument("--version", action="version", version=f"fabricrca {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="find the root cause of host path faults")
    an.add_argument("case", help="case JSON file listing evidence sources")
    an.add_argument("--symptom", help="event id of the symptom to analyse (default: first path fault)")
    an.add_argument("--all", action="store_true", help="analyse every path fault")
    an.add_argument("--window", type=float, default=600, help="seconds before the symptom to search (default 600)")
    an.add_argument("--after", type=float, default=120, help="seconds after the symptom to search")
    an.add_argument("--skew", type=float, default=2.0, help="clock tolerance in seconds for ordering")
    an.add_argument("--retriever", choices=["builtin", "llamaindex"], default="builtin")
    an.add_argument("--embed-model", default="nomic-embed-text")
    an.add_argument("--llm", choices=["none", "ollama"], default="none")
    an.add_argument("--model", default="qwen2.5:7b")
    an.add_argument("--ollama-host", default="http://localhost:11434")
    an.add_argument("--markdown", help="write the report to a Markdown file")
    an.add_argument("--json", help="write the result as JSON")
    an.set_defaults(func=cmd_analyze)
    ev = sub.add_parser("events", help="print the normalised event stream")
    ev.add_argument("case")
    ev.set_defaults(func=cmd_events)
    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
