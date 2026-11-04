# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""Fabric device map used to join host, switch and array events.

``topology.json``::

    {"name_server": [{"switch": "edge-a", "port": "1/4", "wwn": "10:00:...", "alias": "dbhost1_hba0"}],
     "array_ports": [{"array": "ARRAY-01", "port": "CTRL-A-2", "wwn": "50:00:..."}]}

The name server tells us which switch port each WWN (initiator or target) is
logged in to; ``array_ports`` maps array port names to target WWNs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .schema import Event, norm_wwn


@dataclass
class Topology:
    wwn_to_switch_port: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    switch_port_to_wwns: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)
    array_port_to_wwn: Dict[Tuple[str, str], str] = field(default_factory=dict)
    wwn_to_array_port: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    aliases: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict) -> "Topology":
        t = cls()
        for e in d.get("name_server", []):
            w = norm_wwn(e["wwn"])
            key = (e["switch"], str(e["port"]))
            t.wwn_to_switch_port[w] = key
            t.switch_port_to_wwns.setdefault(key, []).append(w)
            if e.get("alias"):
                t.aliases[w] = e["alias"]
        for e in d.get("array_ports", []):
            w = norm_wwn(e["wwn"])
            t.array_port_to_wwn[(e["array"], str(e["port"]))] = w
            t.wwn_to_array_port[w] = (e["array"], str(e["port"]))
        return t

    @classmethod
    def from_file(cls, path: Optional[str]) -> "Topology":
        if not path:
            return cls()
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def enrich(self, events: List[Event]) -> None:
        """Attach the WWNs behind each switch/array port so events can be joined."""
        for e in events:
            if e.source == "switch" and e.port:
                for w in self.switch_port_to_wwns.get((e.system, e.port), []):
                    if w not in e.wwns:
                        e.wwns.append(w)
            elif e.source == "array" and e.port:
                w = self.array_port_to_wwn.get((e.system, e.port))
                if w and w not in e.wwns:
                    e.wwns.append(w)

    def label(self, wwn: str) -> str:
        a = self.aliases.get(wwn)
        return f"{wwn} ({a})" if a else wwn
