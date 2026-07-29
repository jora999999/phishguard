"""Adapter de persistance : in-memory, thread-safe.

Choix assumé pour un projet de portfolio : pas de base de données à
provisionner, démarrage instantané. Le port AnalysisRepositoryPort permet
de brancher SQLite/PostgreSQL plus tard sans toucher au domaine.
"""
from __future__ import annotations

import threading
from collections import OrderedDict

from ..domain.models import AnalysisResult
from ..domain.ports import AnalysisRepositoryPort


class InMemoryAnalysisRepository(AnalysisRepositoryPort):
    def __init__(self, max_items: int = 500):
        self._items: OrderedDict[str, AnalysisResult] = OrderedDict()
        self._lock = threading.Lock()
        self._max = max_items

    def save(self, result: AnalysisResult) -> None:
        with self._lock:
            self._items[result.analysis_id] = result
            while len(self._items) > self._max:  # éviction FIFO
                self._items.popitem(last=False)

    def get(self, analysis_id: str) -> AnalysisResult | None:
        with self._lock:
            return self._items.get(analysis_id)

    def list_all(self) -> list[AnalysisResult]:
        with self._lock:
            return list(reversed(self._items.values()))  # plus récent d'abord
