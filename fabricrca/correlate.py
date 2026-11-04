# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""Evidence-first root-cause correlation across host, fabric and array.

Given a host symptom (a multipath path fault), the engine:

1. identifies the path: initiator WWN and target WWN
2. joins them through the fabric device map to the initiator's switch port,
   the target's switch port and the target's array port
3. retrieves events in a time window around the symptom (temporal filter +
   semantic ranking) and keeps those on the joined resources
4. scores competing hypotheses using the *order* of evidence:

   * physical fault on the target-side switch port (optic / CRC / link)
   * physical fault on the initiator-side switch port
   * array-side fault (controller or array port)
   * independent host HBA fault
   * switch restart

   The hypothesis whose evidence starts earliest on the path wins.  Its most
   specific event is the culprit, earlier evidence on the same resource are
   precursors, and later events on connected endpoints are its victims.  A fault on the switch side shows up
   on the switch first and then at the endpoints; a genuinely failing HBA
   shows up on the host first with no earlier switch-side alarm.

5. returns the culprit, its victims, the cited evidence and why each
   alternative was rejected.  Every claim cites event ids that were actually
   retrieved.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import schema as S
from .index import EventIndex
from .schema import Event
from .topology import Topology

_SPECIFICITY = {S.SW_OPTIC_RX_LOW: 3, S.SW_OPTIC_TX_LOW: 3, S.SW_OPTIC_FAULT: 3, S.SW_CRC_THRESHOLD: 2.5,
                S.SW_LINK_RESET: 2, S.SW_PORT_DOWN: 1.5, S.ARRAY_CONTROLLER_FAULT: 3, S.ARRAY_PORT_DOWN: 1.5,
                S.HOST_HBA_ERROR: 3, S.HOST_HBA_LINK_DOWN: 2, S.SW_REBOOT: 3.5}
_RECOVERY = {S.SW_PORT_UP, S.ARRAY_PORT_UP, S.HOST_PATH_RESTORED}


@dataclass
class Hypothesis:
    name: str
    title: str
    culprit: Optional[Event]
    score: float
    support: List[Event] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    start: float = float("inf")          # time of the first event in this hypothesis' cluster

    @property
    def viable(self) -> bool:
        return self.culprit is not None and self.score > 0


@dataclass
class RCAResult:
    symptom: Event
    initiator: Optional[str]
    target: Optional[str]
    joined: Dict[str, Optional[Tuple[str, str]]]
    retrieved: List[Event]
    best: Hypothesis
    alternatives: List[Hypothesis]
    victims: List[Event]
    recovery: List[Event]
    confidence: float
    precursors: List[Event] = field(default_factory=list)

    @property
    def cited_ids(self) -> List[str]:
        ids = ([self.best.culprit.id] if self.best.culprit else []) + [p.id for p in self.precursors] \
            + [v.id for v in self.victims]
        return list(dict.fromkeys(ids))

    def to_dict(self) -> Dict:
        return {
            "symptom": self.symptom.id,
            "root_cause": self.best.title,
            "hypothesis": self.best.name,
            "culprit_event": self.best.culprit.id if self.best.culprit else None,
            "precursor_events": [p.id for p in self.precursors],
            "victim_events": [v.id for v in self.victims],
            "recovery_events": [v.id for v in self.recovery],
            "confidence": round(self.confidence, 2),
            "initiator": self.initiator, "target": self.target,
            "joined_resources": {k: list(v) if v else None for k, v in self.joined.items()},
            "rejected": [{"hypothesis": h.name, "score": round(h.score, 2),
                          "reason": "; ".join(h.contradictions) or "no supporting evidence in window"}
                         for h in self.alternatives],
            "retrieved_events": [e.id for e in self.retrieved],
        }


def find_symptoms(events: Sequence[Event]) -> List[Event]:
    return [e for e in events if e.event_type == S.HOST_PATH_FAULT]


def _classify_path(symptom: Event, topo: Topology) -> Tuple[Optional[str], Optional[str]]:
    ini = tgt = None
    for w in symptom.wwns:
        if w in topo.wwn_to_array_port:
            tgt = w
        elif ini is None:
            ini = w
    if tgt is None and len(symptom.wwns) > 1:
        tgt = symptom.wwns[1]
    return ini, tgt


def _culprit(events: List[Event], limit_ts: float) -> Tuple[Optional[Event], float]:
    """Pick the culprit of one hypothesis among events up to ``limit_ts``.

    Returns (most specific event - earliest on ties, start time of the cluster).
    Earlier, less specific events on the same resource are its precursors.
    """
    cands = [e for e in events if e.ts <= limit_ts]
    if not cands:
        return None, float("inf")
    best = max(cands, key=lambda e: (_SPECIFICITY.get(e.event_type, 1), -e.ts))
    return best, min(e.ts for e in cands)


def analyze(symptom: Event, index: EventIndex, topo: Topology, before: float = 600, after: float = 120,
            skew: float = 2.0, k: int = 40) -> RCAResult:
    ini, tgt = _classify_path(symptom, topo)
    init_sp = topo.wwn_to_switch_port.get(ini) if ini else None
    tgt_sp = topo.wwn_to_switch_port.get(tgt) if tgt else None
    tgt_ap = topo.wwn_to_array_port.get(tgt) if tgt else None
    switches = {sp[0] for sp in (init_sp, tgt_sp) if sp}
    path_wwns: Set[str] = {w for w in (ini, tgt) if w}

    query = symptom.text() + " link down optic rx power port fault reset controller hba error reboot"
    ranked = index.search(query, symptom.ts, before, after, k=k, wwns=path_wwns)
    # make sure every event on a joined resource in the window is considered, even if ranked low
    in_window = [index.events[i] for i in index.window(symptom.ts, before, after)]

    def on_path(e: Event) -> bool:
        if e.source == "switch":
            return (e.system, e.port) in (init_sp, tgt_sp) or (e.event_type == S.SW_REBOOT and e.system in switches)
        if e.source == "array":
            return bool(tgt_ap) and e.system == tgt_ap[0] and (e.port in (None, tgt_ap[1]))
        return e.system == symptom.system and (bool(path_wwns & set(e.wwns)) or
                                               e.attrs.get("scsi_host") == symptom.attrs.get("scsi_host"))

    retrieved = list({e.id: e for e in [e for e, _ in ranked] + [e for e in in_window if on_path(e)]}.values())
    path_events = sorted([e for e in retrieved if on_path(e)], key=lambda e: e.ts)

    sw_init = [e for e in path_events if e.source == "switch" and (e.system, e.port) == init_sp
               and e.event_type in S.PHYSICAL_SWITCH_EVENTS]
    sw_tgt = [e for e in path_events if e.source == "switch" and (e.system, e.port) == tgt_sp
              and e.event_type in S.PHYSICAL_SWITCH_EVENTS]
    arr = [e for e in path_events if e.source == "array" and e.event_type in (S.ARRAY_PORT_DOWN, S.ARRAY_CONTROLLER_FAULT)]
    hba = [e for e in path_events if e.source == "host" and e.event_type in (S.HOST_HBA_ERROR, S.HOST_HBA_LINK_DOWN)]
    reboots = [e for e in path_events if e.event_type == S.SW_REBOOT]
    limit = symptom.ts + skew

    hyps: List[Hypothesis] = []

    def first_before(evts: List[Event], ts: float) -> Optional[Event]:
        c = [e for e in evts if e.ts < ts - skew]
        return min(c, key=lambda e: e.ts) if c else None

    def switch_port_hyp(name: str, title: str, evts: List[Event], competitor: List[Event], comp_label: str) -> Hypothesis:
        c, start = _culprit(evts, limit)
        h = Hypothesis(name, title, c, 0.0, support=list(evts), start=start)
        if c is None:
            return h
        h.score = _SPECIFICITY.get(c.event_type, 1)
        if start < symptom.ts - skew:
            h.score += 1.0
        earlier = first_before(competitor, start)
        if earlier:
            h.score -= 2.5
            h.contradictions.append(f"{comp_label} event {earlier.id} precedes it by {start - earlier.ts:.0f}s")
        return h

    hyps.append(switch_port_hyp("switch_port_fault_target_side",
                                f"Physical-layer fault on switch port {tgt_sp[0]} {tgt_sp[1]} (target side)" if tgt_sp else "",
                                sw_tgt, arr, "array-side"))
    hyps.append(switch_port_hyp("switch_port_fault_initiator_side",
                                f"Physical-layer fault on switch port {init_sp[0]} {init_sp[1]} (initiator side)" if init_sp else "",
                                sw_init, hba, "host HBA"))

    # array side
    c, start = _culprit(arr, limit)
    h = Hypothesis("array_side_fault", f"Array-side fault on {tgt_ap[0]} port {tgt_ap[1]}" if tgt_ap else "Array-side fault",
                   c, 0.0, support=arr, start=start)
    if c:
        h.score = _SPECIFICITY.get(c.event_type, 1) + (1.0 if start < symptom.ts - skew else 0)
        earlier = first_before(sw_tgt, start)
        if earlier:
            h.score -= 2.5
            h.contradictions.append(f"switch-side {earlier.event_type} {earlier.id} precedes it by {start - earlier.ts:.0f}s")
    hyps.append(h)

    # independent host HBA fault
    c, start = _culprit(hba, limit)
    h = Hypothesis("host_hba_fault", f"Independent host HBA fault on {symptom.system} "
                   f"({c.device if c and c.device else symptom.attrs.get('scsi_host', 'HBA')})", c, 0.0, support=hba,
                   start=start)
    if c:
        h.score = _SPECIFICITY.get(c.event_type, 1) + (0.5 if start < symptom.ts - skew else 0)
        earlier = first_before(sw_init + sw_tgt + reboots, start)
        if earlier:
            h.score -= 2.5
            h.contradictions.append(f"switch-side {earlier.event_type} {earlier.id} precedes the host event by "
                                    f"{start - earlier.ts:.0f}s")
    else:
        fabric_before = [e for e in sw_init + sw_tgt + arr + reboots if e.ts <= limit]
        if fabric_before:
            h.contradictions.append("no host HBA event, and fabric/array alarms on the path precede the path fault")
        else:
            h.culprit, h.score, h.start = symptom, 0.75, symptom.ts
            h.title = f"Host-side fault suspected on {symptom.system} (no fabric or array evidence in window)"
            h.contradictions.append("unconfirmed: no HBA event found; check HBA logs and cabling")
    hyps.append(h)

    c, start = _culprit(reboots, limit)
    hyps.append(Hypothesis("switch_restart", f"Switch {c.system} restart" if c else "Switch restart", c,
                           _SPECIFICITY[S.SW_REBOOT] if c else 0.0, support=reboots, start=start))

    for hh in hyps:
        if hh.culprit is None and not hh.contradictions:
            hh.contradictions.append("no supporting event in window")

    hyps.sort(key=lambda x: (-x.score, x.culprit.ts if x.culprit else float("inf")))
    best = hyps[0] if hyps[0].viable else Hypothesis("unknown", "No root cause found in the retrieved evidence",
                                                      None, 0.0, contradictions=["no viable hypothesis"])
    alternatives = [x for x in hyps if x is not best]
    for x in alternatives:
        if x.culprit is not None and best.culprit is not None and not x.contradictions:
            if x.start >= best.start:
                x.contradictions.append(f"its first event comes {x.start - best.start:.0f}s after the winning "
                                        f"evidence {best.culprit.id}, so it is a consequence, not the cause")
            else:
                x.contradictions.append(f"weaker evidence (score {x.score:.1f} vs {best.score:.1f})")
    pos = sum(max(0.0, x.score) for x in hyps)
    confidence = (max(0.0, best.score) / pos) if pos else 0.0

    victims: List[Event] = []
    recovery: List[Event] = []
    precursors: List[Event] = []
    if best.culprit is not None:
        cul = best.culprit
        for e in path_events:
            if e is cul:
                continue
            if e.ts < cul.ts and any(e is s for s in best.support):
                precursors.append(e)            # earlier evidence of the same fault
            elif e.ts >= best.start - skew:
                (recovery if e.event_type in _RECOVERY else victims).append(e)
        if symptom not in victims and symptom is not best.culprit:
            victims.append(symptom)
        victims.sort(key=lambda e: e.ts)
    return RCAResult(symptom, ini, tgt, {"initiator_switch_port": init_sp, "target_switch_port": tgt_sp,
                                         "target_array_port": tgt_ap},
                     retrieved, best, alternatives, victims, recovery, confidence, precursors)
