"""Adapter d'export : rapport d'incident en Markdown et PDF (ReportLab)."""
from __future__ import annotations

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from ..domain.models import AnalysisResult, Verdict
from ..domain.ports import ReportExporterPort

VERDICT_LABELS = {
    Verdict.PHISHING: "PHISHING",
    Verdict.SUSPICIOUS: "SUSPECT",
    Verdict.LEGITIMATE: "LÉGITIME",
}
VERDICT_COLORS = {
    Verdict.PHISHING: colors.HexColor("#c0392b"),
    Verdict.SUSPICIOUS: colors.HexColor("#b9770e"),
    Verdict.LEGITIMATE: colors.HexColor("#1e8449"),
}


class ReportExporter(ReportExporterPort):
    def to_markdown(self, r: AnalysisResult) -> str:
        lines = [
            f"# Rapport d'incident PhishGuard AI — {r.analysis_id}",
            "",
            f"- **Date d'analyse** : {r.analyzed_at}",
            f"- **Verdict** : **{VERDICT_LABELS[r.verdict]}** — score final **{r.final_score}/100**",
            f"- **Score des règles** : {r.rules_score}/100 · **Ajustement LLM** : "
            f"{r.llm.adjustment:+d} (modèle : `{r.llm.model}`)",
            "",
            "## Courriel analysé",
            f"- **Objet** : {r.email.subject}",
            f"- **Expéditeur** : {r.email.sender_display} <{r.email.sender}>".strip(),
            f"- **Reply-To** : {r.email.reply_to or '—'}",
            f"- **Pièces jointes** : {', '.join(r.email.attachments) or '—'}",
            "",
            "## Signaux détectés (traçabilité du score)",
        ]
        if r.signals:
            lines += ["| Règle | Signal | Points | Preuve |", "|---|---|---|---|"]
            lines += [f"| `{s.rule_id}` | {s.name} | +{s.weight} | {s.evidence} |"
                      for s in r.signals]
        else:
            lines.append("Aucun signal déclenché.")
        lines += ["", "## Explication", r.llm.explanation or "—", "", "## Recommandations"]
        lines += [f"{i}. {rec}" for i, rec in enumerate(r.llm.recommendations, 1)] or ["—"]
        lines += ["", "---",
                  "*Rapport généré automatiquement par PhishGuard AI (projet défensif, "
                  "données synthétiques).*"]
        return "\n".join(lines)

    def to_pdf(self, r: AnalysisResult) -> bytes:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=LETTER,
                                topMargin=1.6 * cm, bottomMargin=1.6 * cm)
        ss = getSampleStyleSheet()
        h1 = ParagraphStyle("H1", parent=ss["Title"], fontSize=16, spaceAfter=6)
        h2 = ParagraphStyle("H2", parent=ss["Heading2"], fontSize=12,
                            textColor=colors.HexColor("#1a2733"))
        body = ParagraphStyle("Body", parent=ss["BodyText"], fontSize=9.5, leading=13)
        verdict_style = ParagraphStyle("V", parent=ss["Heading2"], fontSize=13,
                                       textColor=VERDICT_COLORS[r.verdict])

        story = [
            Paragraph("Rapport d'incident — PhishGuard AI", h1),
            Paragraph(f"Analyse {r.analysis_id} · {r.analyzed_at}", body),
            Spacer(1, 8),
            Paragraph(f"Verdict : {VERDICT_LABELS[r.verdict]} — {r.final_score}/100",
                      verdict_style),
            Paragraph(f"Score des règles : {r.rules_score}/100 · "
                      f"Ajustement LLM : {r.llm.adjustment:+d} ({r.llm.model})", body),
            Spacer(1, 10),
            Paragraph("Courriel analysé", h2),
            Paragraph(f"<b>Objet :</b> {_esc(r.email.subject)}", body),
            Paragraph(f"<b>Expéditeur :</b> {_esc(r.email.sender_display)} "
                      f"&lt;{_esc(r.email.sender)}&gt;", body),
            Paragraph(f"<b>Reply-To :</b> {_esc(r.email.reply_to) or '—'}", body),
            Paragraph(f"<b>Pièces jointes :</b> "
                      f"{_esc(', '.join(r.email.attachments)) or '—'}", body),
            Spacer(1, 10),
            Paragraph("Signaux détectés", h2),
        ]
        if r.signals:
            rows = [["Règle", "Signal", "Pts", "Preuve"]] + [
                [s.rule_id, s.name, f"+{s.weight}",
                 Paragraph(_esc(s.evidence), body)] for s in r.signals]
            t = Table(rows, colWidths=[3.4 * cm, 4.2 * cm, 1.2 * cm, 9.2 * cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a2733")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c8d1d9")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1),
                 [colors.white, colors.HexColor("#f2f5f7")]),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("Aucun signal déclenché.", body))
        story += [Spacer(1, 10), Paragraph("Explication", h2),
                  Paragraph(_esc(r.llm.explanation) or "—", body),
                  Spacer(1, 10), Paragraph("Recommandations", h2)]
        story += [Paragraph(f"{i}. {_esc(rec)}", body)
                  for i, rec in enumerate(r.llm.recommendations, 1)]
        doc.build(story)
        return buf.getvalue()


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
