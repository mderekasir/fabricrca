# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
import datetime as dt
import os
import unittest
from pathlib import Path

from fabricrca import EventIndex, analyze, find_symptoms
from fabricrca import schema as S
from fabricrca.cli import load_case
from fabricrca.llm import verify
from fabricrca.parsers import DEFAULT_SWITCH_RULES, parse_multipath_ll, parse_rule_log
from fabricrca.schema import parse_time

EX = Path(__file__).resolve().parent.parent / "examples"


def run_case(name, **kw):
    events, topo, _ = load_case(str(EX / name / "case.json"))
    symptom = find_symptoms(events)[0]
    return analyze(symptom, EventIndex(events), topo, **kw), events


class ParserTests(unittest.TestCase):
    def test_multipath_ll(self):
        paths = parse_multipath_ll((EX / "multipath_ll.txt").read_text())
        self.assertEqual([(p.map, p.dev, p.hctl, p.scsi_host) for p in paths],
                         [("mpatha", "sdc", "3:0:0:1", "host3"), ("mpatha", "sdd", "4:0:0:1", "host4")])

    def test_switch_rules(self):
        ev = parse_rule_log(["2026-09-24T03:13:58Z sw monitor: port 2/3 rx power -15 dBm below threshold",
                             "2026-09-24T03:14:03Z sw portd: port 2/3 link down (no light)",
                             "garbage line"], "switch", "sw", DEFAULT_SWITCH_RULES)
        self.assertEqual([(e.event_type, e.port) for e in ev], [(S.SW_OPTIC_RX_LOW, "2/3"), (S.SW_PORT_DOWN, "2/3")])

    def test_json_lines_event(self):
        ev = parse_rule_log(['{"timestamp": "2026-09-24T03:00:00Z", "event_type": "SW_REBOOT", "message": "x"}'],
                            "switch", "sw", DEFAULT_SWITCH_RULES)
        self.assertEqual(ev[0].event_type, S.SW_REBOOT)

    def test_time_formats_and_skew(self):
        a = parse_time("2026-09-24T03:14:02Z")
        b = parse_time("Sep 24 03:14:02", year=2026)
        c = parse_time("2026-09-24 03:14:00", offset_s=2)
        self.assertEqual(a, b)
        self.assertEqual(a, c)

    def test_host_events_get_path_wwns(self):
        events, _, _ = load_case(str(EX / "sfp_failure" / "case.json"))
        fault = find_symptoms(events)[0]
        self.assertEqual(fault.wwns, ["10:00:00:00:00:00:d1:01", "50:00:00:00:00:00:a1:02"])
        self.assertEqual(fault.attrs.get("remaining_paths"), 1)


class CorrelationTests(unittest.TestCase):
    def test_sfp_failure_is_switch_side_not_hba(self):
        r, _ = run_case("sfp_failure")
        self.assertEqual(r.best.name, "switch_port_fault_target_side")
        self.assertEqual(r.best.culprit.event_type, S.SW_OPTIC_RX_LOW)
        self.assertIn(S.SW_CRC_THRESHOLD, [p.event_type for p in r.precursors])
        types = {v.event_type for v in r.victims}
        self.assertTrue({S.HOST_PATH_FAULT, S.ARRAY_PORT_DOWN} <= types)
        rejected = {h.name: h for h in r.alternatives}
        self.assertLessEqual(rejected["host_hba_fault"].score, 0)
        self.assertLess(rejected["array_side_fault"].score, 0)

    def test_hba_failure_is_host_side(self):
        r, _ = run_case("hba_failure")
        self.assertEqual(r.best.name, "host_hba_fault")
        self.assertEqual(r.best.culprit.event_type, S.HOST_HBA_ERROR)
        # the switch saw the HBA's link drop *after* the HBA error: a victim, not a cause
        self.assertIn(S.SW_PORT_DOWN, [v.event_type for v in r.victims])

    def test_window_excludes_far_events(self):
        r, _ = run_case("sfp_failure", before=30)
        self.assertNotIn(S.SW_CRC_THRESHOLD, [e.event_type for e in r.retrieved if e.port == "2/3"])

    def test_cited_ids_are_retrieved(self):
        r, _ = run_case("sfp_failure")
        self.assertTrue(set(r.cited_ids) <= {e.id for e in r.retrieved})

    def test_no_evidence_suspects_host(self):
        events, topo, _ = load_case(str(EX / "sfp_failure" / "case.json"))
        only_host = [e for e in events if e.source == "host"]
        r = analyze(find_symptoms(only_host)[0], EventIndex(only_host), topo)
        self.assertEqual(r.best.name, "host_hba_fault")
        self.assertLess(r.best.score, 1)


class LLMVerificationTests(unittest.TestCase):
    def test_rejects_uncited_and_misordered_answers(self):
        r, _ = run_case("sfp_failure")
        bad = verify({"root_cause": "x", "culprit_event_id": "S-deadbeef", "victim_event_ids": [], "reasoning": ""}, r)
        self.assertFalse(bad.valid)
        host = r.symptom.id
        misordered = verify({"root_cause": "x", "culprit_event_id": r.victims[-1].id,
                             "victim_event_ids": [r.best.culprit.id], "reasoning": ""}, r)
        self.assertFalse(misordered.valid)
        good = verify({"root_cause": "optic", "culprit_event_id": r.best.culprit.id,
                       "victim_event_ids": [host], "reasoning": ""}, r)
        self.assertTrue(good.valid)
        self.assertTrue(good.agrees_with_engine)


if __name__ == "__main__":
    unittest.main()
