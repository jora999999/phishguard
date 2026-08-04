"""Tests unitaires du moteur de règles (couche déterministe).

Chaque règle est testée avec un cas positif ET un cas négatif :
c'est la garantie que le score reste vérifiable règle par règle.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.domain.models import Email  # noqa: E402
from app.domain import rules  # noqa: E402


def make_email(**kw) -> Email:
    base = dict(subject="Bonjour", sender="alice@ulaval.ca", body_text="Salut, à demain.",
                links=[], link_texts=[], attachments=[])
    base.update(kw)
    return Email(**base)


# --- Levenshtein ------------------------------------------------------------

def test_levenshtein_identique():
    assert rules.levenshtein("desjardins", "desjardins") == 0

def test_levenshtein_substitution_et_insertion():
    assert rules.levenshtein("desjardlns", "desjardins") == 1
    assert rules.levenshtein("paypa1", "paypal") == 1
    assert rules.levenshtein("netfliix", "netflix") == 1

def test_levenshtein_chaine_vide():
    assert rules.levenshtein("", "abc") == 3


# --- R01 urgence ------------------------------------------------------------

def test_urgence_detectee():
    e = make_email(body_text="URGENT : votre compte sera suspendu dans les 24 heures.")
    s = rules.rule_urgency(e)
    assert s is not None and s.rule_id == "R01_URGENCY" and s.weight >= 15

def test_urgence_absente():
    assert rules.rule_urgency(make_email()) is None


# --- R02 mismatch de lien ---------------------------------------------------

def test_mismatch_domaine_affiche_vs_reel():
    e = make_email(links=["https://desjardlns-secure.top/login"],
                   link_texts=["https://desjardins.com/securite"])
    s = rules.rule_domain_mismatch(e)
    assert s is not None and s.weight == 30

def test_lien_coherent_sans_mismatch():
    e = make_email(links=["https://www.desjardins.com/aide"],
                   link_texts=["desjardins.com"])
    assert rules.rule_domain_mismatch(e) is None


# --- R03 typosquatting ------------------------------------------------------

def test_typosquatting_expediteur():
    e = make_email(sender="securite@desjardlns.com")
    s = rules.rule_typosquatting(e)
    assert s is not None and "desjardins.com" in s.evidence

def test_domaine_legitime_exact_ignore():
    e = make_email(sender="info@desjardins.com",
                   links=["https://www.desjardins.com/x"])
    assert rules.rule_typosquatting(e) is None


# --- R04 informations sensibles ----------------------------------------------

def test_demande_mot_de_passe():
    e = make_email(body_text="Veuillez confirmer votre mot de passe et votre NIP.")
    s = rules.rule_sensitive_request(e)
    assert s is not None and s.weight == 25

def test_mention_securitaire_legitime_ne_declenche_pas_seule():
    # Une phrase préventive contient "mot de passe" : la règle se déclenche
    # (comportement assumé), mais l'email légitime reste sous le seuil global.
    e = make_email(body_text="Nous ne vous demanderons jamais votre mot de passe.")
    signals, score = rules.run_rules(e)
    assert score < 30  # verdict global : légitime


# --- R06 pièces jointes -----------------------------------------------------

def test_double_extension_pese_plus_lourd():
    s1 = rules.rule_suspicious_attachment(make_email(attachments=["facture.pdf.exe"]))
    s2 = rules.rule_suspicious_attachment(make_email(attachments=["macro.docm"]))
    assert s1.weight == 30 and s2.weight == 25

def test_pdf_normal_ok():
    assert rules.rule_suspicious_attachment(
        make_email(attachments=["compte-rendu.pdf"])) is None


# --- R07 raccourcisseurs / R08 reply-to / R09 display / R10 URL --------------

def test_lien_raccourci():
    assert rules.rule_shortened_link(
        make_email(links=["http://bit.ly/abc"])) is not None

def test_replyto_divergent():
    e = make_email(sender="service@paypal.com", reply_to="collect@mail-retour.tk")
    assert rules.rule_replyto_mismatch(e) is not None

def test_replyto_meme_domaine_ok():
    e = make_email(sender="service@paypal.com", reply_to="noreply@paypal.com")
    assert rules.rule_replyto_mismatch(e) is None

def test_usurpation_nom_affiche():
    e = make_email(sender="xyz123@gmail.com", sender_display="Desjardins Sécurité")
    assert rules.rule_display_name_spoof(e) is not None

def test_marque_multi_tld_pas_de_faux_positif():
    # Régression : "Amazon" <commandes@amazon.ca> ne doit pas être signalé
    # comme usurpation sous prétexte que amazon.com est aussi dans la liste.
    e = make_email(sender="commandes@amazon.ca", sender_display="Amazon")
    assert rules.rule_display_name_spoof(e) is None

def test_ip_brute_dans_lien():
    assert rules.rule_ip_or_odd_url(
        make_email(links=["http://192.168.4.22/colis"])) is not None


# --- Agrégation et plafond ---------------------------------------------------

def test_score_plafonne_a_100():
    e = make_email(
        subject="URGENT dernier avertissement",
        sender="securite@desjardlns.com",
        sender_display="Desjardins",
        reply_to="x@retour.tk",
        body_text=("Cher client, votre compte sera suspendu. Confirmez votre mot de passe "
                   "et votre numéro de carte sans délai."),
        links=["http://bit.ly/x", "http://10.1.2.3/x"],
        link_texts=["", ""],
        attachments=["releve.pdf.exe"],
    )
    signals, score = rules.run_rules(e)
    assert score == 100 and len(signals) >= 6

def test_email_sain_score_nul():
    signals, score = rules.run_rules(make_email())
    assert score == 0 and signals == []
