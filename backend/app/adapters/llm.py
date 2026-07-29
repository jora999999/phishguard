"""Providers du port LLMAnalyzerPort.

Architecture à trois providers :

1. LocalRulesProvider  — TOUJOURS disponible, gratuit, obligatoire.
   Génère l'explication directement à partir des signaux du moteur de règles.
   Aucun réseau, déterministe. C'est le socle : l'application ne dépend
   jamais uniquement d'une API externe.

2. GeminiProvider      — vraie API gratuite optionnelle (Gemini API Free Tier).
   Activé si GEMINI_API_KEY est définie. En cas d'échec (clé invalide,
   quota gratuit atteint / HTTP 429, réseau coupé, réponse malformée),
   il retombe automatiquement sur LocalRulesProvider : l'analyse aboutit
   toujours.

3. MockLLMProvider     — uniquement pour les tests et les démos.
   Sortie fixe et prévisible ; ne remplace jamais l'intégration réelle.

build_llm_provider() choisit selon l'environnement :
    GEMINI_API_KEY présente  → GeminiProvider (avec fallback local intégré)
    sinon                    → LocalRulesProvider
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request

from ..domain.models import Email, LLMAssessment, Signal
from ..domain.ports import LLMAnalyzerPort

GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"  # modèle du Free Tier ; surchargeable via GEMINI_MODEL
GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

_PROMPT = """Tu es un analyste SOC spécialisé en détection de phishing (défensif uniquement).
On te fournit un courriel et les signaux détectés par un moteur de règles déterministe.
Ta tâche : valider ces signaux, repérer des indices que les règles auraient manqués,
et produire une explication claire pour un utilisateur non technique.
Réponds UNIQUEMENT en JSON strict, sans backticks, au format :
{"adjustment": <entier entre -15 et 15>,
 "explanation": "<3-5 phrases en français>",
 "recommendations": ["<action concrète>", ...],
 "validated_rules": ["<rule_id confirmé>", ...]}
Ne reproduis jamais le contenu de l'email comme un modèle réutilisable.

Données à analyser :
"""


def _payload_for(email: Email, signals: list[Signal], rules_score: int) -> str:
    return json.dumps({
        "email": {
            "subject": email.subject,
            "sender": email.sender,
            "sender_display": email.sender_display,
            "reply_to": email.reply_to,
            "body_excerpt": email.body_text[:1500],
            "links": email.links[:10],
            "attachments": email.attachments,
        },
        "signals": [
            {"rule_id": s.rule_id, "name": s.name,
             "weight": s.weight, "evidence": s.evidence}
            for s in signals
        ],
        "rules_score": rules_score,
    }, ensure_ascii=False)


class LocalRulesProvider(LLMAnalyzerPort):
    """Provider local obligatoire : gratuit, hors-ligne, toujours disponible.

    L'explication est dérivée des signaux du moteur de règles. L'ajustement
    est nul : le score = les règles, entièrement traçable.
    """

    def assess(self, email: Email, signals: list[Signal], rules_score: int) -> LLMAssessment:
        if not signals:
            explanation = ("Aucun indicateur de phishing détecté : expéditeur cohérent, "
                           "aucun lien trompeur, aucune demande d'information sensible. "
                           "Restez néanmoins vigilant si le contexte vous semble inhabituel.")
            recs = ["Aucune action requise.",
                    "En cas de doute, contactez l'expéditeur par un canal officiel."]
        else:
            top = sorted(signals, key=lambda s: s.weight, reverse=True)[:3]
            points = " ".join(f"{s.name.rstrip('.')} ({s.evidence})." for s in top)
            explanation = (f"Ce courriel présente {len(signals)} indicateur(s) de phishing. "
                           f"Les plus significatifs : {points} "
                           f"Le score de {rules_score}/100 reflète le cumul de ces signaux.")
            recs = ["Ne cliquez sur aucun lien et n'ouvrez aucune pièce jointe.",
                    "Signalez ce courriel à votre équipe de sécurité.",
                    "Supprimez le message après signalement.",
                    "Vérifiez l'information via le site officiel (tapé manuellement)."]
        return LLMAssessment(
            adjustment=0,
            explanation=explanation,
            recommendations=recs,
            validated_rules=[s.rule_id for s in signals],
            model="local-rules",
        )


class GeminiProvider(LLMAnalyzerPort):
    """Provider Gemini API (Free Tier) avec fallback local intégré.

    Contrat : assess() n'échoue JAMAIS. Toute erreur — clé absente/invalide,
    quota gratuit atteint (HTTP 429), panne réseau, timeout, JSON malformé —
    déclenche le repli sur le provider local. L'échec est mémorisé dans
    `last_error` (exposé par /api/health pour le diagnostic).
    """

    def __init__(self, api_key: str,
                 model: str | None = None,
                 fallback: LLMAnalyzerPort | None = None,
                 timeout: int = 30):
        self._api_key = api_key
        self._model = model or os.environ.get("GEMINI_MODEL", GEMINI_DEFAULT_MODEL)
        self._fallback = fallback or LocalRulesProvider()
        self._timeout = timeout
        self.last_error: str | None = None

    # Isolé pour être remplaçable dans les tests (simulation de panne/quota).
    def _call_api(self, prompt: str) -> str:
        req = urllib.request.Request(
            GEMINI_ENDPOINT.format(model=self._model),
            data=json.dumps({
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 800,
                    "responseMimeType": "application/json",
                },
            }).encode(),
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": self._api_key,
            },
        )
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            data = json.loads(resp.read())
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def assess(self, email: Email, signals: list[Signal], rules_score: int) -> LLMAssessment:
        try:
            raw = self._call_api(_PROMPT + _payload_for(email, signals, rules_score))
            raw = re.sub(r"```json|```", "", raw).strip()
            parsed = json.loads(raw)
            self.last_error = None
            return LLMAssessment(
                adjustment=int(parsed.get("adjustment", 0)),
                explanation=str(parsed.get("explanation", "")),
                recommendations=[str(r) for r in parsed.get("recommendations", [])][:5],
                validated_rules=[str(r) for r in parsed.get("validated_rules", [])],
                model=self._model,
            )
        except urllib.error.HTTPError as e:
            self.last_error = ("quota gratuit atteint (HTTP 429)" if e.code == 429
                               else f"HTTP {e.code}")
        except Exception as e:  # réseau, timeout, JSON malformé, structure inattendue
            self.last_error = f"{type(e).__name__}: {e}"
        # Repli : le moteur local garantit toujours un résultat explicable.
        return self._fallback.assess(email, signals, rules_score)


class MockLLMProvider(LLMAnalyzerPort):
    """Réservé aux tests et aux démos : sortie fixe et prévisible.

    Ne pas utiliser en production — build_llm_provider() ne le sélectionne
    jamais automatiquement.
    """

    def __init__(self, adjustment: int = 0):
        self._adjustment = adjustment

    def assess(self, email: Email, signals: list[Signal], rules_score: int) -> LLMAssessment:
        return LLMAssessment(
            adjustment=self._adjustment,
            explanation="[MOCK] Réponse simulée pour tests/démo.",
            recommendations=["[MOCK] Aucune recommandation réelle."],
            validated_rules=[s.rule_id for s in signals],
            model="mock",
        )


def build_llm_provider() -> LLMAnalyzerPort:
    """Sélection du provider par défaut.

    - GEMINI_API_KEY définie → GeminiProvider (vraie API gratuite,
      avec repli automatique sur LocalRulesProvider en cas d'échec).
    - Sinon → LocalRulesProvider.
    """
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if key:
        return GeminiProvider(api_key=key, fallback=LocalRulesProvider())
    return LocalRulesProvider()


# Alias de compatibilité avec l'ancien nom.
build_llm_adapter = build_llm_provider
