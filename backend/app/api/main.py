"""API FastAPI de PhishGuard AI — adapter d'entrée HTTP.

Endpoints :
  POST /api/analyze            analyse un email (JSON)
  POST /api/analyze/batch      analyse un lot (JSON[] ou fichiers .eml/.json/.txt)
  GET  /api/analyses           liste des analyses (résumé)
  GET  /api/analyses/{id}      détail complet
  GET  /api/analyses/{id}/report.md | report.pdf
  GET  /api/health             sonde de vie (+ mode LLM actif)
"""
from __future__ import annotations

import json
import os
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

from ..adapters.email_parser import from_eml, from_json
from ..adapters.llm import GeminiProvider, build_llm_provider
from ..adapters.report import ReportExporter
from ..adapters.repository import InMemoryAnalysisRepository
from ..domain.analyzer import PhishingAnalyzer
from ..domain.models import AnalysisResult

app = FastAPI(title="PhishGuard AI", version="1.0.0",
              description="Analyseur de phishing explicable — règles déterministes + LLM.")

# CORS : restricting to allowed origins (from FRONTEND_URL env var).
# In dev: localhost:5173 (Vite dashboard)
# In prod: set FRONTEND_URL as a comma-separated list of allowed domains
allowed_origins = os.getenv("FRONTEND_URL", "http://localhost:5173").split(",")
allowed_origins = [origin.strip() for origin in allowed_origins]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins,
                   allow_methods=["*"], allow_headers=["*"])

# Composition root : on branche les adapters sur les ports du domaine.
_repo = InMemoryAnalysisRepository()
_llm = build_llm_provider()
_analyzer = PhishingAnalyzer(llm=_llm, repository=_repo)
_exporter = ReportExporter()


class EmailIn(BaseModel):
    subject: str = ""
    sender: str = ""
    sender_display: str = ""
    reply_to: str = ""
    body_text: str = Field("", description="Corps texte ou HTML")
    links: Optional[list[str]] = None
    link_texts: Optional[list[str]] = None
    attachments: list[str] = []


def _summary(r: AnalysisResult) -> dict:
    return {
        "analysis_id": r.analysis_id,
        "analyzed_at": r.analyzed_at,
        "subject": r.email.subject,
        "sender": r.email.sender,
        "final_score": r.final_score,
        "rules_score": r.rules_score,
        "llm_adjustment": r.llm.adjustment,
        "verdict": r.verdict.value,
        "signal_count": len(r.signals),
    }


def _detail(r: AnalysisResult) -> dict:
    return {
        **_summary(r),
        "sender_display": r.email.sender_display,
        "reply_to": r.email.reply_to,
        "body_text": r.email.body_text,
        "links": r.email.links,
        "attachments": r.email.attachments,
        "signals": [{"rule_id": s.rule_id, "name": s.name, "weight": s.weight,
                     "evidence": s.evidence, "description": s.description}
                    for s in r.signals],
        "llm": {"model": r.llm.model, "adjustment": r.llm.adjustment,
                "explanation": r.llm.explanation,
                "recommendations": r.llm.recommendations,
                "validated_rules": r.llm.validated_rules},
    }


@app.get("/api/health")
def health():
    info = {"status": "ok", "llm_provider": type(_llm).__name__}
    if isinstance(_llm, GeminiProvider):
        # Diagnostic : None = dernier appel réussi ; sinon raison du repli local.
        info["gemini_last_error"] = _llm.last_error
    return info


@app.post("/api/analyze")
def analyze(payload: EmailIn):
    result = _analyzer.analyze(from_json(payload.model_dump()))
    return _detail(result)


@app.post("/api/analyze/batch")
async def analyze_batch(files: list[UploadFile]):
    """Mode batch : accepte des fichiers .eml, .json ou .txt et retourne un agrégé."""
    results, errors = [], []
    for f in files:
        raw = await f.read()
        try:
            name = (f.filename or "").lower()
            if name.endswith(".json"):
                email = from_json(json.loads(raw))
            else:  # .eml / .txt → parsing RFC 822
                email = from_eml(raw)
            results.append((f.filename, _analyzer.analyze(email)))
        except Exception as exc:
            errors.append({"file": f.filename, "error": str(exc)})
    verdicts = [r.verdict.value for _, r in results]
    return {
        "total": len(files),
        "analyzed": len(results),
        "errors": errors,
        "aggregate": {
            "phishing": verdicts.count("phishing"),
            "suspicious": verdicts.count("suspicious"),
            "legitimate": verdicts.count("legitimate"),
            "avg_score": round(sum(r.final_score for _, r in results)
                               / max(1, len(results)), 1),
        },
        "results": [{"file": fn, **_summary(r)} for fn, r in results],
    }


@app.get("/api/analyses")
def list_analyses():
    return [_summary(r) for r in _repo.list_all()]


@app.get("/api/analyses/{analysis_id}")
def get_analysis(analysis_id: str):
    r = _repo.get(analysis_id)
    if not r:
        raise HTTPException(404, "Analyse introuvable")
    return _detail(r)


@app.get("/api/analyses/{analysis_id}/report.md", response_class=PlainTextResponse)
def report_md(analysis_id: str):
    r = _repo.get(analysis_id)
    if not r:
        raise HTTPException(404, "Analyse introuvable")
    return PlainTextResponse(_exporter.to_markdown(r), media_type="text/markdown",
                             headers={"Content-Disposition":
                                      f'attachment; filename="phishguard-{analysis_id}.md"'})


@app.get("/api/analyses/{analysis_id}/report.pdf")
def report_pdf(analysis_id: str):
    r = _repo.get(analysis_id)
    if not r:
        raise HTTPException(404, "Analyse introuvable")
    return Response(_exporter.to_pdf(r), media_type="application/pdf",
                    headers={"Content-Disposition":
                             f'attachment; filename="phishguard-{analysis_id}.pdf"'})
