"""Ports de l'architecture hexagonale.

Le domaine définit CE dont il a besoin ; les adapters (couche externe)
fournissent COMMENT. On peut donc remplacer le LLM, l'export ou le
stockage sans toucher au cœur métier.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from .models import AnalysisResult, Email, LLMAssessment, Signal


class LLMAnalyzerPort(ABC):
    """Port sortant : enrichissement/validation des signaux par un LLM."""

    @abstractmethod
    def assess(self, email: Email, signals: list[Signal], rules_score: int) -> LLMAssessment:
        """Retourne une évaluation LLM. Doit être sûr : jamais d'exception propagée."""


class ReportExporterPort(ABC):
    """Port sortant : export d'un rapport d'incident."""

    @abstractmethod
    def to_markdown(self, result: AnalysisResult) -> str: ...

    @abstractmethod
    def to_pdf(self, result: AnalysisResult) -> bytes: ...


class AnalysisRepositoryPort(ABC):
    """Port sortant : persistance des analyses (in-memory, SQLite, etc.)."""

    @abstractmethod
    def save(self, result: AnalysisResult) -> None: ...

    @abstractmethod
    def get(self, analysis_id: str) -> AnalysisResult | None: ...

    @abstractmethod
    def list_all(self) -> list[AnalysisResult]: ...
