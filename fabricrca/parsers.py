# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""Parsers for host, switch and array evidence -> common :class:`Event` schema.

Host side (standard Linux formats):
  * ``multipath -ll`` snapshot - maps sdX / major:minor to H:C:T:L and map name
  * multipathd / kernel syslog - path failed / reinstated, HBA link down, HBA errors
  * an HBA map (``hostN`` -> initiator WWN) and target map (``H:C:T`` -> target WWN),
    produced by ``scripts/collect_host_info.sh`` from ``/sys/class/fc_*``

Switch and array side: log formats differ by vendor and release, so these are
rule-driven.  A rule is a regex with optional named groups ``port``, ``wwn``
and ``value`` plus the event type and severity it produces.  Generic default
rules are included; supply your own JSON rule file for your platforms.
Structured JSON-lines events are also accepted for all three sources.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import schema as S
from .schema import Event, norm_wwn, parse_time

# ---------------------------------------------------------------------------
# Timestamp prefix handling
# ---------------------------------------------------------------------------
_ISO_PREFIX = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$")
_SYSLOG_PREFIX = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")


def split_timestamp(line: str, year: Optional[int], offset_s: float):
    for rx in (_ISO_PREFIX, _SYSLOG_PREFIX):
        m = rx.match(line)
        if m:
            return parse_time(m.group("ts"), year, offset_s), m.group("rest")
    return None, line


# ---------------------------------------------------------------------------
# Host: multipath -ll
# ---------------------------------------------------------------------------
_MAP_HDR = re.compile(r"^(?P<name>\S+)\s+\((?P<wwid>[^)]+)\)\s+(?P<dm>dm-\d+)")
_MAP_HDR2 = re.compile(r"^(?P<wwid>[0-9a-f]{20,})\s+(?P<dm>dm-\d+)")
_PATH = re.compile(r"(?P<hctl>\d+:\d+:\d+:\d+)\s+(?P<dev>sd[a-z]+)\s+(?P<majmin>\d+:\d+)\s+(?P<dm_state>\w+)\s+(?P<chk_state>\w+)")


@dataclass
class PathInfo:
    map: str
    wwid: str
    hctl: str
    dev: str
    majmin: str
    dm_state: str
    chk_state: str

    @property
    def scsi_host(self) -> str:
        return f"host{self.hctl.split(':')[0]}"

    @property
    def hct(self) -> str:
        return ":".join(self.hctl.split(":")[:3])


def parse_multipath_ll(text: str) -> List[PathInfo]:
    paths: List[PathInfo] = []
    cur_map, cur_wwid = None, None
    for line in text.splitlines():
        m = _MAP_HDR.match(line) or _MAP_HDR2.match(line)
        if m:
            cur_wwid = m.group("wwid")
            cur_map = m.groupdict().get("name") or cur_wwid
            continue
        p = _PATH.search(line)
        if p and cur_map:
            paths.append(PathInfo(cur_map, cur_wwid or "", p.group("hctl"), p.group("dev"), p.group("majmin"),
                                  p.group("dm_state"), p.group("chk_state")))
    return paths


@dataclass
class HostContext:
    host: str
    paths: List[PathInfo]
    hba_map: Dict[str, str]          # "host3" -> initiator WWN
    target_map: Dict[str, str]       # "3:0:0" -> target WWN

    @classmethod
    def load(cls, host: str, multipath_ll: Optional[str], info: Optional[Dict[str, Any]]) -> "HostContext":
        info = info or {}
        return cls(host, parse_multipath_ll(multipath_ll or ""),
                   {k: norm_wwn(v) for k, v in info.get("hba_map", {}).items()},
                   {k: norm_wwn(v) for k, v in info.get("target_map", {}).items()})

    def lookup(self, token: str) -> Optional[PathInfo]:
        for p in self.paths:
            if token in (p.dev, p.majmin, p.hctl):
                return p
        return None

    def wwns_for_path(self, p: PathInfo) -> List[str]:
        out = []
        if p.scsi_host in self.hba_map:
            out.append(self.hba_map[p.scsi_host])
        if p.hct in self.target_map:
            out.append(self.target_map[p.hct])
        return out


_HOST_RULES: List[Tuple[re.Pattern, str, str]] = [
    (re.compile(r"multipathd\[?\d*\]?:\s*(?:(?P<map>\S+):\s*)?(?P<path>sd[a-z]+|\d+:\d+):?\s*mark as failed", re.I), S.HOST_PATH_FAULT, "error"),
    (re.compile(r"checker failed path (?P<path>\d+:\d+) in map (?P<map>\S+)", re.I), S.HOST_PATH_FAULT, "error"),
    (re.compile(r"multipath: \d+:\d+: Failing path (?P<path>\d+:\d+)", re.I), S.HOST_PATH_FAULT, "error"),
    (re.compile(r"(?:(?P<map>\S+):\s*)?(?P<path>sd[a-z]+|\d+:\d+)\s*(?:-\s*\w+ checker reports path is up|: reinstated)", re.I), S.HOST_PATH_RESTORED, "info"),
    (re.compile(r"(?:\bhost(?P<host>\d+)\b|\bscsi(?P<host2>\d+)\b).*link (?:is )?down|link down.*\bhost(?P<host3>\d+)\b", re.I), S.HOST_HBA_LINK_DOWN, "error"),
    (re.compile(r"(?:\bhost(?P<host>\d+)\b).*(?:firmware|adapter|hba)\s+(?:error|fault|dump|reset|hang)", re.I), S.HOST_HBA_ERROR, "critical"),
]
_REMAINING = re.compile(r"(?P<map>\S+): remaining active paths: (?P<n>\d+)")


def parse_host_log(lines: Iterable[str], ctx: HostContext, year: Optional[int] = None,
                   offset_s: float = 0.0) -> List[Event]:
    events: List[Event] = []
    remaining: Dict[str, int] = {}
    for raw in lines:
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue
        ts, rest = split_timestamp(raw, year, offset_s)
        if ts is None:
            continue
        if m := _REMAINING.search(rest):
            remaining[m.group("map")] = int(m.group("n"))
            if events and events[-1].attrs.get("map") == m.group("map"):
                events[-1].attrs["remaining_paths"] = int(m.group("n"))
            continue
        for rx, etype, sev in _HOST_RULES:
            m = rx.search(rest)
            if not m:
                continue
            g = {k: v for k, v in m.groupdict().items() if v}
            wwns: List[str] = []
            device = None
            attrs: Dict[str, Any] = {}
            if "path" in g:
                p = ctx.lookup(g["path"])
                device = g["path"]
                if p:
                    device = f"{p.map}/{p.dev}"
                    attrs.update(map=p.map, hctl=p.hctl, scsi_host=p.scsi_host)
                    wwns = ctx.wwns_for_path(p)
                elif "map" in g:
                    attrs["map"] = g["map"]
            hnum = g.get("host") or g.get("host2") or g.get("host3")
            if hnum:
                attrs["scsi_host"] = f"host{hnum}"
                if f"host{hnum}" in ctx.hba_map:
                    wwns = [ctx.hba_map[f"host{hnum}"]]
                device = f"host{hnum}"
            if etype == S.HOST_PATH_FAULT and not wwns and not device:
                continue
            events.append(Event(ts, "host", ctx.host, etype, sev, rest.strip(), wwns=wwns, device=device,
                                raw=raw, attrs=attrs))
            break
    return events


# ---------------------------------------------------------------------------
# Rule-driven switch / array parsing
# ---------------------------------------------------------------------------
DEFAULT_SWITCH_RULES: List[Dict[str, str]] = [
    {"pattern": r"(?i)\bport\s+(?P<port>[\w/]+).*\brx power\b.*\b(?:below|low)\b", "event_type": S.SW_OPTIC_RX_LOW, "severity": "error"},
    {"pattern": r"(?i)\bport\s+(?P<port>[\w/]+).*\btx power\b.*\b(?:below|low)\b", "event_type": S.SW_OPTIC_TX_LOW, "severity": "error"},
    {"pattern": r"(?i)\b(?:sfp|optic|transceiver)\b.*\b(?:fault|failed|failure|removed)\b.*\bport\s+(?P<port>[\w/]+)", "event_type": S.SW_OPTIC_FAULT, "severity": "error"},
    {"pattern": r"(?i)\bport\s+(?P<port>[\w/]+).*\b(?:sfp|optic|transceiver)\b.*\b(?:fault|failed|failure|removed)\b", "event_type": S.SW_OPTIC_FAULT, "severity": "error"},
    {"pattern": r"(?i)\bport\s+(?P<port>[\w/]+).*\bcrc\b.*\b(?:threshold|exceeded)\b", "event_type": S.SW_CRC_THRESHOLD, "severity": "warning"},
    {"pattern": r"(?i)\bport\s+(?P<port>[\w/]+).*\blink reset\b", "event_type": S.SW_LINK_RESET, "severity": "warning"},
    {"pattern": r"(?i)\bport\s+(?P<port>[\w/]+).*\b(?:link down|offline|went down|no light|no_light|no sync)\b", "event_type": S.SW_PORT_DOWN, "severity": "error"},
    {"pattern": r"(?i)\bport\s+(?P<port>[\w/]+).*\b(?:link up|online)\b", "event_type": S.SW_PORT_UP, "severity": "info"},
    {"pattern": r"(?i)\b(?:switch|system|chassis)\b.*\b(?:reboot(?:ed|ing)?|restart(?:ed|ing)?|cold start|warm start)\b", "event_type": S.SW_REBOOT, "severity": "critical"},
]

DEFAULT_ARRAY_RULES: List[Dict[str, str]] = [
    {"pattern": r"(?i)\bcontroller\b.*\b(?:fault|failed|failure|panic|halted)\b", "event_type": S.ARRAY_CONTROLLER_FAULT, "severity": "critical"},
    {"pattern": r"(?i)\bport\s+(?P<port>[\w\-/.]+).*\b(?:link down|link-down|offline|link lost)\b", "event_type": S.ARRAY_PORT_DOWN, "severity": "error"},
    {"pattern": r"(?i)\bport\s+(?P<port>[\w\-/.]+).*\b(?:link up|link-up|online)\b", "event_type": S.ARRAY_PORT_UP, "severity": "info"},
]

_SYSTEM_PREFIX = re.compile(r"^(?P<system>[A-Za-z0-9_.\-]+)(?:\s+\S+\[\d+\])?:?\s+(?P<msg>.*)$")


def compile_rules(rules: List[Dict[str, str]]) -> List[Tuple[re.Pattern, str, str]]:
    return [(re.compile(r["pattern"]), r["event_type"], r.get("severity", "warning")) for r in rules]


def parse_rule_log(lines: Iterable[str], source: str, system: str, rules: List[Dict[str, str]],
                   year: Optional[int] = None, offset_s: float = 0.0) -> List[Event]:
    compiled = compile_rules(rules)
    events: List[Event] = []
    for raw in lines:
        raw = raw.rstrip("\n")
        if not raw.strip():
            continue
        if raw.lstrip().startswith("{"):
            events.append(event_from_json(json.loads(raw), source, system, offset_s))
            continue
        ts, rest = split_timestamp(raw, year, offset_s)
        if ts is None:
            continue
        for rx, etype, sev in compiled:
            m = rx.search(rest)
            if not m:
                continue
            g = {k: v for k, v in m.groupdict().items() if v}
            wwns = [norm_wwn(g["wwn"])] if "wwn" in g else []
            attrs = {"value": g["value"]} if "value" in g else {}
            events.append(Event(ts, source, system, etype, sev, rest.strip(), wwns=wwns, port=g.get("port"),
                                raw=raw, attrs=attrs))
            break
    return events


def event_from_json(d: Dict[str, Any], source: str, system: str, offset_s: float = 0.0) -> Event:
    return Event(parse_time(str(d["timestamp"]), offset_s=offset_s), d.get("source", source),
                 d.get("system", system), d["event_type"], d.get("severity", "warning"), d.get("message", ""),
                 wwns=d.get("wwns", []), port=d.get("port"), device=d.get("device"),
                 raw=json.dumps(d, sort_keys=True), attrs=d.get("attrs", {}), id=d.get("id", ""))


def load_rules(path: Optional[str], default: List[Dict[str, str]]) -> List[Dict[str, str]]:
    if not path:
        return default
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("rules", data) if isinstance(data, dict) else data
