"""Mode batch en ligne de commande : analyse un dossier de .eml/.json/.txt
et produit un rapport agrégé (console + Markdown).

Usage :
    python scripts/batch_analyze.py <dossier> [--out rapport_batch.md]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.adapters.email_parser import from_eml, from_json  # noqa: E402
from app.adapters.llm import build_llm_provider  # noqa: E402
from app.adapters.repository import InMemoryAnalysisRepository  # noqa: E402
from app.domain.analyzer import PhishingAnalyzer  # noqa: E402

VERDICT_ICON = {"phishing": "🔴", "suspicious": "🟠", "legitimate": "🟢"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyse batch d'un dossier d'emails.")
    ap.add_argument("folder", type=Path, help="Dossier contenant des .eml/.json/.txt")
    ap.add_argument("--out", type=Path, default=Path("rapport_batch.md"))
    args = ap.parse_args()

    files = sorted(p for p in args.folder.iterdir()
                   if p.suffix.lower() in {".eml", ".json", ".txt"})
    if not files:
        print(f"Aucun fichier .eml/.json/.txt dans {args.folder}", file=sys.stderr)
        return 1

    analyzer = PhishingAnalyzer(llm=build_llm_provider(),
                                repository=InMemoryAnalysisRepository(max_items=10_000))
    rows, verdicts = [], Counter()
    for path in files:
        try:
            if path.suffix.lower() == ".json":
                email = from_json(json.loads(path.read_text(encoding="utf-8")))
            else:
                email = from_eml(path.read_bytes())
            r = analyzer.analyze(email)
            verdicts[r.verdict.value] += 1
            rows.append((path.name, r))
            print(f"{VERDICT_ICON[r.verdict.value]} {r.final_score:>3}/100  "
                  f"{path.name}  — {len(r.signals)} signal(aux)")
        except Exception as exc:
            print(f"⚠️  {path.name} : erreur de lecture ({exc})", file=sys.stderr)

    total = len(rows)
    avg = round(sum(r.final_score for _, r in rows) / max(1, total), 1)
    print(f"\n=== Agrégé : {total} emails · score moyen {avg} · "
          f"🔴 {verdicts['phishing']} · 🟠 {verdicts['suspicious']} · "
          f"🟢 {verdicts['legitimate']} ===")

    # Rapport Markdown agrégé
    lines = ["# Rapport batch — PhishGuard AI", "",
             f"- **Fichiers analysés** : {total}",
             f"- **Score moyen** : {avg}/100",
             f"- **Répartition** : {verdicts['phishing']} phishing · "
             f"{verdicts['suspicious']} suspects · {verdicts['legitimate']} légitimes",
             "", "| Fichier | Score | Verdict | Signaux |", "|---|---|---|---|"]
    for name, r in sorted(rows, key=lambda x: -x[1].final_score):
        sig = ", ".join(s.rule_id for s in r.signals) or "—"
        lines.append(f"| {name} | {r.final_score}/100 | {r.verdict.value} | {sig} |")
    args.out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Rapport écrit : {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
