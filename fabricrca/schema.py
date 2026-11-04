# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""Common event schema shared by every parser (paper Sec. III-A).

Every host, switch and array event is normalised to :class:`Event` so that
retrieval and correlation work the same regardless of origin.  Resource
identifiers are kept as separate fields so that events can be joined through
the fabric's device map (initiator WWN <-> switch port <-> array port).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SOURCES = ("host", "switch", "array")
SEVERITIES = ("info", "warning", "error", "critical")

# Generic, vendor-neutral event types
HOST_PATH_FAULT = "HOST_PATH_FAULT"        # multipath path marked failed
HOST_PATH_RESTORED = "HOST_PATH_RESTORED"
HOST_HBA_LINK_DOWN = "HOST_HBA_LINK_DOWN"
HOST_HBA_ERROR = "HOST_HBA_ERROR"          # driver / firmware error on the HBA itself
SW_OPTIC_RX_LOW = "SW_OPTIC_RX_LOW"        # optic receive power below threshold
SW_OPTIC_TX_LOW = "SW_OPTIC_TX_LOW"
SW_OPTIC_FAULT = "SW_OPTIC_FAULT"
SW_PORT_DOWN = "SW_PORT_DOWN"
SW_PORT_UP = "SW_PORT_UP"
SW_LINK_RESET = "SW_LINK_RESET"
SW_CRC_THRESHOLD = "SW_CRC_THRESHOLD"
SW_REBOOT = "SW_REBOOT"
ARRAY_PORT_DOWN = "ARRAY_PORT_DOWN"
ARRAY_PORT_UP = "ARRAY_PORT_UP"
ARRAY_CONTROLLER_FAULT = "ARRAY_CONTROLLER_FAULT"

PHYSICAL_SWITCH_EVENTS = {SW_OPTIC_RX_LOW, SW_OPTIC_TX_LOW, SW_OPTIC_FAULT, SW_PORT_DOWN, SW_LINK_RESET,
                          SW_CRC_THRESHOLD}


def norm_wwn(w: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", w).lower()
    if len(h) != 16:
        raise ValueError(f"not a WWN: {w!r}")
    return ":".join(h[i:i + 2] for i in range(0, 16, 2))


@dataclass
class Event:
    timestamp: dt.datetime                 # timezone-aware, UTC
    source: str                            # host | switch | array
    system: str                            # host name, switch name or array name
    event_type: str
    severity: str
    message: str
    wwns: List[str] = field(default_factory=list)
    port: Optional[str] = None             # switch port or array port
    device: Optional[str] = None           # host-side device, e.g. multipath map or sdX
    raw: str = ""
    attrs: Dict[str, Any] = field(default_factory=dict)
    id: str = ""

    def __post_init__(self) -> None:
        if self.source not in SOURCES:
            raise ValueError(f"source must be one of {SOURCES}")
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=dt.timezone.utc)
        self.wwns = [norm_wwn(w) for w in self.wwns]
        if not self.id:
            h = hashlib.sha1(f"{self.timestamp.isoformat()}|{self.system}|{self.event_type}|{self.raw or self.message}"
                             .encode()).hexdigest()[:8]
            self.id = f"{self.source[0].upper()}-{h}"

    @property
    def ts(self) -> float:
        return self.timestamp.timestamp()

    def text(self) -> str:
        """Text used for semantic retrieval."""
        parts = [self.source, self.system, self.event_type.replace("_", " ").lower(), self.message]
        if self.port:
            parts.append(f"port {self.port}")
        if self.device:
            parts.append(self.device)
        parts += self.wwns
        return " ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d

    def short(self) -> str:
        loc = f" port {self.port}" if self.port else (f" {self.device}" if self.device else "")
        return f"[{self.id}] {self.timestamp:%Y-%m-%d %H:%M:%S} {self.source}:{self.system}{loc} {self.event_type} - {self.message}"


_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
                                         "Nov", "Dec"), 1)}


def parse_time(s: str, year: Optional[int] = None, offset_s: float = 0.0) -> dt.datetime:
    """Accepts ISO-8601 (with or without zone) and classic syslog ``Mon DD HH:MM:SS``.

    ``offset_s`` corrects a known clock skew for the source (added to the time).
    Times without a zone are treated as UTC.
    """
    s = s.strip()
    t: Optional[dt.datetime] = None
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00").replace(" ", "T", 1) if "T" not in s and " " in s
                                      and s[:4].isdigit() else s.replace("Z", "+00:00"))
    except ValueError:
        m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})", s)
        if not m:
            raise ValueError(f"unrecognised timestamp {s!r}")
        t = dt.datetime(year or dt.datetime.now(dt.timezone.utc).year, _MONTHS[m.group(1)], int(m.group(2)),
                        int(m.group(3)), int(m.group(4)), int(m.group(5)))
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc) + dt.timedelta(seconds=offset_s)
