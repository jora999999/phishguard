"""Entités du domaine PhishGuard AI.

Couche la plus interne de l'architecture hexagonale :
aucune dépendance vers FastAPI, le LLM ou la persistance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class Verdict(str, Enum):
    LEGITIMATE = "legitimate"      # score < 30
    SUSPICIOUS = "suspicious"      # 30 <= score < 60
    PHISHING = "phishing"          # score >= 60


@dataclass(frozen=True)
class Email:
    """Représentation normalisée d'un courriel à analyser."""
    subject: str
    sender: str                      # adresse réelle (From)
    body_text: str
    sender_display: str = ""         # nom affiché ("Desjardins Sécurité")
    reply_to: str = ""
    links: list[str] = field(default_factory=list)        # URLs extraites du corps
    link_texts: list[str] = field(default_factory=list)   # textes d'ancre associés
    attachments: list[str] = field(default_factory=list)  # noms de fichiers


@dataclass(frozen=True)
class Signal:
    """Un signal détecté par UNE règle : la brique de traçabilité du score."""
    rule_id: str          # ex. "R03_TYPOSQUATTING"
    name: str             # nom lisible
    weight: int           # points ajoutés au score (0-100)
    evidence: str         # preuve concrète extraite de l'email
    description: str      # pourquoi ce signal est un indicateur de phishing


@dataclass
class LLMAssessment:
    """Contribution de la couche LLM — bornée et séparée du score des règles."""
    adjustment: int = 0            # borné à [-15, +15] par le scorer
    explanation: str = ""          # explication en langage clair
    recommendations: list[str] = field(default_factory=list)
    validated_rules: list[str] = field(default_factory=list)  # rule_ids confirmés
    model: str = "none"            # "none" = mode dégradé sans LLM


@dataclass
class AnalysisResult:
    """Résultat complet, entièrement traçable : score = somme(signaux) + ajustement LLM."""
    email: Email
    signals: list[Signal]
    rules_score: int               # somme pondérée plafonnée à 100
    llm: LLMAssessment
    final_score: int               # rules_score + llm.adjustment, borné [0, 100]
    verdict: Verdict
    analysis_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    @staticmethod
    def verdict_for(score: int) -> Verdict:
        if score >= 60:
            return Verdict.PHISHING
        if score >= 30:
            return Verdict.SUSPICIOUS
        return Verdict.LEGITIMATE
