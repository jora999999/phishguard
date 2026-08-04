"""Évaluation du détecteur contre le dataset synthétique (120 emails).

Mesure précision, rappel, F1 et exactitude au seuil de décision (score >= 30
= signalé). Le test échoue si la qualité régresse sous les seuils minimaux :
c'est un garde-fou de non-régression pour toute modification des règles.

Exécuté avec l'adapter LLM heuristique (déterministe) → résultats reproductibles.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.adapters.email_parser import from_json  # noqa: E402
from app.adapters.llm import LocalRulesProvider  # noqa: E402
from app.adapters.repository import InMemoryAnalysisRepository  # noqa: E402
from app.domain.analyzer import PhishingAnalyzer  # noqa: E402

DATASET = Path(__file__).resolve().parents[1] / "backend" / "data" / "dataset.json"
DECISION_THRESHOLD = 30  # score >= 30 → l'email est signalé (suspect ou phishing)

MIN_PRECISION = 0.95
MIN_RECALL = 0.90
MIN_ACCURACY = 0.92


def evaluate():
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    analyzer = PhishingAnalyzer(llm=LocalRulesProvider(),
                                repository=InMemoryAnalysisRepository(max_items=1000))
    tp = fp = tn = fn = 0
    misclassified = []
    for item in data:
        result = analyzer.analyze(from_json(item))
        flagged = result.final_score >= DECISION_THRESHOLD
        is_phish = item["label"] == "phishing"
        if flagged and is_phish:
            tp += 1
        elif flagged and not is_phish:
            fp += 1
            misclassified.append((item["id"], result.final_score))
        elif not flagged and is_phish:
            fn += 1
            misclassified.append((item["id"], result.final_score))
        else:
            tn += 1
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-9, precision + recall)
    accuracy = (tp + tn) / len(data)
    return dict(n=len(data), tp=tp, fp=fp, tn=tn, fn=fn, precision=precision,
                recall=recall, f1=f1, accuracy=accuracy, misclassified=misclassified)


def test_dataset_existe_et_equilibre():
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    labels = [d["label"] for d in data]
    assert len(data) >= 100
    assert labels.count("phishing") == labels.count("legitimate")


def test_metriques_minimales():
    m = evaluate()
    print(f"\n=== Évaluation PhishGuard AI (n={m['n']}, seuil={DECISION_THRESHOLD}) ===")
    print(f"TP={m['tp']}  FP={m['fp']}  TN={m['tn']}  FN={m['fn']}")
    print(f"Précision : {m['precision']:.3f} | Rappel : {m['recall']:.3f} | "
          f"F1 : {m['f1']:.3f} | Exactitude : {m['accuracy']:.3f}")
    if m["misclassified"]:
        print("Mal classés :", m["misclassified"])
    assert m["precision"] >= MIN_PRECISION, f"Précision {m['precision']:.3f} < {MIN_PRECISION}"
    assert m["recall"] >= MIN_RECALL, f"Rappel {m['recall']:.3f} < {MIN_RECALL}"
    assert m["accuracy"] >= MIN_ACCURACY, f"Exactitude {m['accuracy']:.3f} < {MIN_ACCURACY}"


if __name__ == "__main__":
    m = evaluate()
    print(json.dumps({k: v for k, v in m.items() if k != "misclassified"}, indent=2))
