"""Service applicatif : orchestre le moteur de règles et la couche LLM.

Garantie de traçabilité : final_score = rules_score + adjustment_LLM,
où l'ajustement LLM est borné à [-15, +15]. Le LLM ne peut jamais, à lui
seul, faire basculer un email clairement légitime en phishing (ou l'inverse).
"""
from __future__ import annotations

from .models import AnalysisResult, Email, LLMAssessment
from .ports import AnalysisRepositoryPort, LLMAnalyzerPort
from .rules import run_rules

LLM_ADJUSTMENT_BOUND = 15


class PhishingAnalyzer:
    def __init__(self, llm: LLMAnalyzerPort, repository: AnalysisRepositoryPort):
        self._llm = llm
        self._repo = repository

    def analyze(self, email: Email) -> AnalysisResult:
        # 1. Couche déterministe — vérifiable et testée unitairement.
        signals, rules_score = run_rules(email)

        # 2. Couche LLM — validation, explication, recommandations.
        try:
            assessment = self._llm.assess(email, signals, rules_score)
        except Exception:  # le LLM ne doit jamais casser l'analyse
            assessment = LLMAssessment(explanation="Couche LLM indisponible ; "
                                                   "score basé uniquement sur les règles.")

        # 3. Ajustement borné : le score reste traçable.
        adj = max(-LLM_ADJUSTMENT_BOUND, min(LLM_ADJUSTMENT_BOUND, assessment.adjustment))
        assessment.adjustment = adj
        final = max(0, min(100, rules_score + adj))

        result = AnalysisResult(
            email=email,
            signals=signals,
            rules_score=rules_score,
            llm=assessment,
            final_score=final,
            verdict=AnalysisResult.verdict_for(final),
        )
        self._repo.save(result)
        return result
