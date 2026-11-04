# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""fabricrca - correlate host multipath loss with Fibre Channel fabric and array events.

Companion code for "From Symptom to Root Cause: AI-Driven Correlation of Host
Multipath Loss with Fabric and Array Events via Local RAG"
(D. A. M. Caleb, 2026).
"""
__version__ = "0.1.0"
__author__ = "Derek Asir Muthurajan Caleb"
__copyright__ = "Copyright (c) 2026 Derek Asir Muthurajan Caleb"

from .correlate import RCAResult, analyze, find_symptoms
from .index import EventIndex
from .schema import Event
from .topology import Topology

__all__ = ["RCAResult", "analyze", "find_symptoms", "EventIndex", "Event", "Topology", "__version__"]
