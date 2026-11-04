# Author / Owner / Publisher: Derek Asir Muthurajan Caleb
# Copyright (c) 2026 Derek Asir Muthurajan Caleb
# SPDX-License-Identifier: Apache-2.0
"""Time-partitioned retrieval over normalised events (paper Sec. III-B).

Retrieval = temporal filter (events within a window of the symptom) followed
by semantic ranking of the event text.

* ``EventIndex`` - built-in: sorted time index (bisect) + BM25 ranking, plus a
  boost for events that share a resource (WWN) with the query.  No
  dependencies, deterministic, good enough for log text.
* ``LlamaIndexRetriever`` - optional: a LlamaIndex ``VectorStoreIndex`` with a
  local Ollama embedding model and a timestamp metadata filter.
"""
from __future__ import annotations

import bisect
import math
import re
from collections import Counter
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .schema import Event

_TOKEN = re.compile(r"[a-z0-9]+(?:[:/][a-z0-9]+)*")


def tokenize(text: str) -> List[str]:
    return _TOKEN.findall(text.lower())


class BM25:
    def __init__(self, docs: Sequence[List[str]], k1: float = 1.4, b: float = 0.75) -> None:
        self.docs, self.k1, self.b = docs, k1, b
        self.avgdl = sum(map(len, docs)) / max(len(docs), 1)
        df: Counter = Counter()
        for d in docs:
            df.update(set(d))
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}
        self.tf = [Counter(d) for d in docs]

    def score(self, query: List[str], i: int) -> float:
        tf, dl, s = self.tf[i], len(self.docs[i]), 0.0
        for t in query:
            if t in tf:
                f = tf[t]
                s += self.idf.get(t, 0) * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * dl / self.avgdl))
        return s


class EventIndex:
    def __init__(self, events: Iterable[Event]) -> None:
        self.events: List[Event] = sorted(events, key=lambda e: e.ts)
        self._times = [e.ts for e in self.events]
        self._bm25 = BM25([tokenize(e.text()) for e in self.events])
        self.by_id = {e.id: e for e in self.events}

    def __len__(self) -> int:
        return len(self.events)

    def window(self, center: float, before: float, after: float) -> List[int]:
        lo = bisect.bisect_left(self._times, center - before)
        hi = bisect.bisect_right(self._times, center + after)
        return list(range(lo, hi))

    def search(self, query: str, center: float, before: float = 600, after: float = 120, k: int = 25,
               wwns: Optional[Set[str]] = None, wwn_boost: float = 5.0) -> List[Tuple[Event, float]]:
        q = tokenize(query)
        scored = []
        for i in self.window(center, before, after):
            e = self.events[i]
            s = self._bm25.score(q, i)
            if wwns and wwns & set(e.wwns):
                s += wwn_boost
            scored.append((e, s))
        scored.sort(key=lambda x: (-x[1], x[0].ts))
        return scored[:k]


class LlamaIndexRetriever:  # pragma: no cover - requires llama-index and a local embedding model
    """Same contract as ``EventIndex.search`` but backed by a LlamaIndex vector store."""

    def __init__(self, events: Iterable[Event], embed_model: str = "nomic-embed-text",
                 ollama_url: str = "http://localhost:11434") -> None:
        from llama_index.core import Document, VectorStoreIndex
        from llama_index.embeddings.ollama import OllamaEmbedding
        self.events = sorted(events, key=lambda e: e.ts)
        self.by_id = {e.id: e for e in self.events}
        docs = [Document(text=e.text(), doc_id=e.id, metadata={"ts": e.ts, "source": e.source, "event_id": e.id})
                for e in self.events]
        self.index = VectorStoreIndex.from_documents(
            docs, embed_model=OllamaEmbedding(model_name=embed_model, base_url=ollama_url))

    def search(self, query: str, center: float, before: float = 600, after: float = 120, k: int = 25,
               wwns: Optional[Set[str]] = None, wwn_boost: float = 5.0) -> List[Tuple[Event, float]]:
        from llama_index.core.vector_stores import FilterOperator, MetadataFilter, MetadataFilters
        filters = MetadataFilters(filters=[
            MetadataFilter(key="ts", value=center - before, operator=FilterOperator.GTE),
            MetadataFilter(key="ts", value=center + after, operator=FilterOperator.LTE)])
        nodes = self.index.as_retriever(similarity_top_k=k, filters=filters).retrieve(query)
        out = []
        for n in nodes:
            e = self.by_id[n.node.metadata["event_id"]]
            s = float(n.score or 0) + (wwn_boost if wwns and wwns & set(e.wwns) else 0)
            out.append((e, s))
        out.sort(key=lambda x: (-x[1], x[0].ts))
        return out
