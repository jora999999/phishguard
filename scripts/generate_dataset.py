"""Génère un dataset synthétique de 120 courriels (60 phishing / 60 légitimes).

Aucun vrai email n'est copié : les exemples combinent des gabarits inspirés
de patterns publics documentés (urgence, typosquatting, usurpation de marque)
avec des variations aléatoires mais reproductibles (seed fixe).
Le dataset sert exclusivement à ÉVALUER la détection.

Usage : python scripts/generate_dataset.py  → backend/data/dataset.json
"""
from __future__ import annotations

import json
import random
from pathlib import Path

random.seed(42)  # reproductibilité des tests d'évaluation

BRANDS = [
    ("Desjardins", "desjardins.com", "desjardlns.com"),
    ("PayPal", "paypal.com", "paypa1.com"),
    ("Amazon", "amazon.ca", "arnazon-ca.com"),
    ("Microsoft", "microsoft.com", "rnicrosoft.com"),
    ("Netflix", "netflix.com", "netfliix.com"),
    ("Revenu Québec", "revenuquebec.ca", "revenuquebec-remboursement.xyz"),
    ("Postes Canada", "postescanada.ca", "postescanda.ca"),
    ("Interac", "interac.ca", "lnterac.ca"),
]

FIRST = ["Amina", "Youssef", "Camille", "Étienne", "Sofia", "Marc", "Leïla", "Gabriel"]

# --- Gabarits de phishing (patterns publics, jamais de contenu réel copié) ---

def phish_urgent_account(brand, legit, fake, i):
    return {
        "subject": f"URGENT : votre compte {brand} sera suspendu dans 24 heures",
        "sender": f"securite@{fake}",
        "sender_display": f"{brand} Sécurité",
        "body_text": (f"Cher client, nous avons détecté une activité inhabituelle sur votre "
                      f"compte. Vous devez vérifier votre identité dans les 24 heures, sinon "
                      f"votre compte sera suspendu. Confirmez vos identifiants ici : "
                      f'<a href="https://{fake}/verify?id={i}">https://{legit}/securite</a>'),
    }

def phish_refund(brand, legit, fake, i):
    return {
        "subject": f"Remboursement de {random.randint(80, 450)},{random.randint(10,99)} $ disponible",
        "sender": f"remboursement@{fake}",
        "sender_display": brand,
        "reply_to": f"claims{i}@mail-retour.tk",
        "body_text": (f"Cher utilisateur, un remboursement de {random.randint(80,450)},32 $ "
                      f"vous attend. Pour le recevoir, confirmez votre numéro de carte et "
                      f"votre date de naissance sans délai : "
                      f'<a href="http://bit.ly/rb{i}x">Réclamer mon remboursement</a>'),
    }

def phish_parcel(brand, legit, fake, i):
    return {
        "subject": "Votre colis est en attente de livraison",
        "sender": f"livraison@{fake}",
        "sender_display": "Postes Canada",
        "body_text": ("Cher client, votre colis est en attente de livraison depuis 3 jours. "
                      "Des frais de 1,99 $ sont requis. Agissez maintenant : "
                      f'<a href="http://{random.randint(45,220)}.{random.randint(10,250)}.'
                      f'{random.randint(1,250)}.{random.randint(2,250)}/colis{i}">Payer les frais</a>'),
    }

def phish_attachment(brand, legit, fake, i):
    return {
        "subject": f"Facture impayée #{1000 + i} — action immédiate requise",
        "sender": f"comptabilite@{fake}",
        "sender_display": f"{brand} Facturation",
        "body_text": ("Dernier avertissement : votre facture est impayée. Consultez la pièce "
                      "jointe et réglez sans délai pour éviter la fermeture de votre compte."),
        "attachments": [f"facture_{1000 + i}.pdf.exe"],
    }

def phish_prize(brand, legit, fake, i):
    return {
        "subject": "Félicitations, vous avez été sélectionné !",
        "sender": f"promo{i}@offres-gagnant.xyz",
        "sender_display": f"Concours {brand}",
        "body_text": (f"Félicitations, vous avez gagné une carte-cadeau {brand} de 500 $. "
                      f"Confirmez vos informations bancaires pour recevoir votre prix : "
                      f'<a href="https://tinyurl.com/gain{i}">Réclamer maintenant</a>'),
    }

def phish_it_reset(brand, legit, fake, i):
    return {
        "subject": "Votre mot de passe expire aujourd'hui",
        "sender": f"support-ti@{fake}",
        "sender_display": "Support TI",
        "reply_to": f"helpdesk{i}@reponse-ti.ml",
        "body_text": ("Action immédiate : votre mot de passe expire aujourd'hui. "
                      "Vérifiez votre compte pour conserver l'accès à vos courriels : "
                      f'<a href="https://{fake}/reset{i}">https://portail.ulaval.ca</a>'),
    }

PHISH_TEMPLATES = [phish_urgent_account, phish_refund, phish_parcel,
                   phish_attachment, phish_prize, phish_it_reset]

# --- Gabarits légitimes (transactionnels/internes plausibles) ---

def legit_receipt(brand, legit, _f, i):
    return {
        "subject": f"Reçu de votre commande #{78000 + i}",
        "sender": f"commandes@{legit}",
        "sender_display": brand,
        "body_text": (f"Bonjour {random.choice(FIRST)}, merci pour votre commande. Votre reçu "
                      f"est disponible dans votre espace client. Montant : "
                      f"{random.randint(15, 220)},{random.randint(10,99)} $. Vous pouvez suivre "
                      f'la livraison ici : <a href="https://{legit}/commandes/{78000 + i}">'
                      f"{legit}/commandes</a>"),
    }

def legit_newsletter(brand, legit, _f, i):
    return {
        "subject": f"Infolettre {brand} — nouveautés du mois",
        "sender": f"infolettre@{legit}",
        "sender_display": brand,
        "body_text": (f"Bonjour {random.choice(FIRST)}, voici les nouveautés du mois. "
                      f"Pour gérer vos préférences de communication, rendez-vous sur "
                      f'<a href="https://{legit}/preferences">{legit}/preferences</a>. '
                      f"Bonne lecture !"),
    }

def legit_meeting(_b, _l, _f, i):
    return {
        "subject": f"Compte rendu — rencontre d'équipe du sprint {i % 9 + 1}",
        "sender": "genevieve.tremblay@ulaval.ca",
        "sender_display": "Geneviève Tremblay",
        "body_text": (f"Salut {random.choice(FIRST)}, voici le compte rendu de notre rencontre. "
                      "On a convenu de terminer la revue de code avant vendredi et de planifier "
                      "la démo la semaine prochaine. Dis-moi si j'ai oublié quelque chose."),
        "attachments": [f"compte-rendu-sprint-{i % 9 + 1}.pdf"],
    }

def legit_statement(brand, legit, _f, i):
    return {
        "subject": "Votre relevé mensuel est disponible",
        "sender": f"releves@{legit}",
        "sender_display": brand,
        "body_text": (f"Bonjour {random.choice(FIRST)}, votre relevé mensuel est maintenant "
                      f"disponible dans votre espace sécurisé. Connectez-vous comme d'habitude "
                      f"via notre site officiel ou l'application mobile pour le consulter. "
                      f"Nous ne vous demanderons jamais votre mot de passe par courriel."),
    }

def legit_course(_b, _l, _f, i):
    return {
        "subject": f"IFT-{2000 + i % 900} : rappel — remise du TP{i % 4 + 1}",
        "sender": "enseignant@ulaval.ca",
        "sender_display": "Équipe enseignante",
        "body_text": (f"Bonjour à toutes et à tous, petit rappel que le TP{i % 4 + 1} est à "
                      f"remettre dimanche 23 h 59 sur le portail des cours. Les consignes "
                      f"complètes sont dans l'énoncé déjà publié. Bon week-end !"),
    }

def legit_shipping(brand, legit, _f, i):
    return {
        "subject": f"Votre commande #{78000 + i} a été expédiée",
        "sender": f"expedition@{legit}",
        "sender_display": brand,
        "body_text": (f"Bonjour, votre commande a été expédiée aujourd'hui. Numéro de suivi : "
                      f"CA{100000 + i}QC. Suivez votre livraison sur "
                      f'<a href="https://{legit}/suivi/CA{100000 + i}QC">{legit}/suivi</a>.'),
    }

LEGIT_TEMPLATES = [legit_receipt, legit_newsletter, legit_meeting,
                   legit_statement, legit_course, legit_shipping]


def build(n_per_class: int = 60) -> list[dict]:
    dataset = []
    for i in range(n_per_class):
        brand, legit, fake = BRANDS[i % len(BRANDS)]
        p = PHISH_TEMPLATES[i % len(PHISH_TEMPLATES)](brand, legit, fake, i)
        dataset.append({"id": f"phish-{i:03d}", "label": "phishing", **p})
        l = LEGIT_TEMPLATES[i % len(LEGIT_TEMPLATES)](brand, legit, fake, i)
        dataset.append({"id": f"legit-{i:03d}", "label": "legitimate", **l})
    random.shuffle(dataset)
    return dataset


if __name__ == "__main__":
    out = Path(__file__).resolve().parents[1] / "backend" / "data" / "dataset.json"
    data = build()
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    labels = [d["label"] for d in data]
    print(f"Dataset écrit : {out} — {len(data)} emails "
          f"({labels.count('phishing')} phishing / {labels.count('legitimate')} légitimes)")
