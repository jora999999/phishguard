"""Tests de la couche LLM à trois providers.

Vérifie les deux garanties centrales du projet :
1. L'application fonctionne SANS GEMINI_API_KEY (moteur local seul).
2. Si Gemini échoue (quota gratuit atteint, réseau, réponse malformée),
   l'analyse retombe sur le moteur local et aboutit quand même.
Aucun test n'effectue de vrai appel réseau.
"""
import io
import os
import sys
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.adapters.llm import (  # noqa: E402
    GeminiProvider, LocalRulesProvider, MockLLMProvider, build_llm_provider,
)
from app.adapters.repository import InMemoryAnalysisRepository  # noqa: E402
from app.domain.analyzer import PhishingAnalyzer  # noqa: E402
from app.domain.models import Email  # noqa: E402

PHISHING_EMAIL = Email(
    subject="URGENT : votre compte sera suspendu",
    sender="securite@desjardlns.com",
    sender_display="Desjardins",
    body_text="Confirmez votre mot de passe immédiatement : http://desjardlns.com/verif",
    links=["http://desjardlns.com/verif"],
)


def _analyze_with(provider):
    analyzer = PhishingAnalyzer(llm=provider, repository=InMemoryAnalysisRepository())
    return analyzer.analyze(PHISHING_EMAIL)


# --- Garantie 1 : fonctionne sans GEMINI_API_KEY ---------------------------

def test_sans_cle_provider_local_selectionne(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert isinstance(build_llm_provider(), LocalRulesProvider)


def test_sans_cle_analyse_complete_et_explicable(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    result = _analyze_with(build_llm_provider())
    # Score, classification et raisons explicables — toujours présents.
    assert 0 <= result.final_score <= 100
    assert result.verdict in ("legitime", "suspect", "phishing")
    assert result.verdict == "phishing"
    assert len(result.signals) > 0
    assert all(s.evidence for s in result.signals)      # chaque signal a sa preuve
    assert result.llm.explanation                        # explication non vide
    assert result.llm.model == "local-rules"


def test_avec_cle_provider_gemini_selectionne(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fausse-cle-de-test")
    assert isinstance(build_llm_provider(), GeminiProvider)


# --- Garantie 2 : échec Gemini → repli sur le moteur local ------------------

def _gemini_qui_echoue(exc):
    provider = GeminiProvider(api_key="fausse-cle", fallback=LocalRulesProvider())
    provider._call_api = lambda prompt: (_ for _ in ()).throw(exc)
    return provider


def test_quota_gratuit_atteint_http_429_repli_local():
    exc = urllib.error.HTTPError("url", 429, "Too Many Requests", {}, io.BytesIO(b""))
    provider = _gemini_qui_echoue(exc)
    result = _analyze_with(provider)
    assert result.verdict == "phishing"                  # l'analyse aboutit
    assert result.llm.model == "local-rules"             # servie par le moteur local
    assert "429" in provider.last_error


def test_panne_reseau_repli_local():
    provider = _gemini_qui_echoue(urllib.error.URLError("réseau injoignable"))
    result = _analyze_with(provider)
    assert result.verdict == "phishing"
    assert result.llm.model == "local-rules"
    assert provider.last_error is not None


def test_reponse_gemini_malformee_repli_local():
    provider = GeminiProvider(api_key="fausse-cle", fallback=LocalRulesProvider())
    provider._call_api = lambda prompt: "ceci n'est pas du JSON {"
    result = _analyze_with(provider)
    assert result.llm.model == "local-rules"
    assert result.final_score == result.rules_score      # aucun ajustement fantôme


def test_ajustement_gemini_borne_a_15():
    # Même si Gemini renvoyait un ajustement absurde, l'analyseur le borne.
    provider = GeminiProvider(api_key="fausse-cle")
    provider._call_api = lambda prompt: '{"adjustment": 90, "explanation": "x", "recommendations": [], "validated_rules": []}'
    result = _analyze_with(provider)
    assert result.llm.adjustment == 15
    assert result.final_score == min(100, result.rules_score + 15)


# --- MockLLMProvider : réservé aux tests/démos ------------------------------

def test_mock_provider_identifiable_et_jamais_selectionne_par_defaut(monkeypatch):
    result = _analyze_with(MockLLMProvider())
    assert result.llm.model == "mock"
    assert "[MOCK]" in result.llm.explanation
    # Jamais choisi automatiquement, avec ou sans clé.
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    assert not isinstance(build_llm_provider(), MockLLMProvider)
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    assert not isinstance(build_llm_provider(), MockLLMProvider)
