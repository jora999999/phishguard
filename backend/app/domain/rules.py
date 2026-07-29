"""Moteur de règles déterministes de PhishGuard AI.

Chaque règle est une fonction pure Email -> Signal | None.
Le score est la somme des poids, plafonnée à 100 : traçable et vérifiable.
Les poids reflètent la fiabilité de l'indicateur (un mismatch de domaine
est plus incriminant qu'un simple ton urgent).
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from .models import Email, Signal

# ---------------------------------------------------------------------------
# Données de référence
# ---------------------------------------------------------------------------

# Domaines légitimes connus, utilisés pour la détection de typosquatting.
KNOWN_DOMAINS = [
    "desjardins.com", "paypal.com", "amazon.ca", "amazon.com", "microsoft.com",
    "google.com", "apple.com", "netflix.com", "interac.ca", "canada.ca",
    "revenuquebec.ca", "cra-arc.gc.ca", "ulaval.ca", "banquenationale.ca",
    "rbc.com", "bmo.com", "postescanada.ca", "canadapost.ca", "hydroquebec.com",
    "videotron.com", "bell.ca", "outlook.com", "gmail.com", "linkedin.com",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".js", ".jse", ".vbs", ".ps1",
    ".jar", ".docm", ".xlsm", ".pptm", ".hta", ".iso", ".img", ".lnk",
}

# Mots/expressions d'urgence (FR + EN) — insensibles à la casse.
URGENCY_PATTERNS = [
    r"urgent", r"imm[ée]diat", r"dans les (24|48) heures", r"within (24|48) hours",
    r"votre compte sera (suspendu|ferm[ée]|d[ée]sactiv[ée]|bloqu[ée])",
    r"account (will be|has been) (suspended|closed|locked|deactivated)",
    r"derni(er|ère) (avertissement|rappel)", r"final (warning|notice)",
    r"agissez maintenant", r"act now", r"expire (aujourd|bient[ôo]t)",
    r"action (imm[ée]diate|requise)", r"immediate action", r"sans d[ée]lai",
]

# Demandes d'informations sensibles.
SENSITIVE_PATTERNS = [
    r"mot de passe", r"password", r"nip\b", r"\bpin\b", r"num[ée]ro de carte",
    r"card number", r"cvv", r"cvc", r"num[ée]ro d.assurance sociale", r"\bnas\b",
    r"\bsin\b", r"social insurance", r"date de naissance", r"date of birth",
    r"informations bancaires", r"banking (details|information)",
    r"confirmez vos (identifiants|informations)", r"verify your (identity|credentials|account)",
    r"v[ée]rifiez votre (identit[ée]|compte)",
]

# Marqueurs d'incohérence fréquents dans le phishing (générique + maladroit).
INCOHERENCE_PATTERNS = [
    r"cher (client|utilisateur|membre)\b", r"dear (customer|user|member|valued)",
    r"ch[ée]r [ée]?client",              # faute volontairement typique
    r"votre colis est en attente de livraison depuis",
    r"nous avons d[ée]tect[ée] une activit[ée] inhabituelle",
    r"unusual (activity|sign-in)",
    r"f[ée]licitations[, ]+vous avez (gagn[ée]|[ée]t[ée] s[ée]lectionn[ée])",
    r"congratulations[, ]+you (have won|were selected)",
    r"remboursement de \d+[.,]\d{2}\s?\$",
]

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

def levenshtein(a: str, b: str) -> int:
    """Distance d'édition classique, en O(len(a)*len(b)). Implémentée à la main
    pour rester sans dépendance et facilement testable."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1,        # suppression
                            curr[j - 1] + 1,    # insertion
                            prev[j - 1] + cost))  # substitution
        prev = curr
    return prev[-1]


def extract_domain(value: str) -> str:
    """Extrait un domaine normalisé d'une URL ou d'une adresse courriel."""
    value = value.strip().lower()
    if "@" in value and not value.startswith("http"):
        return value.rsplit("@", 1)[-1].strip(">").strip()
    if "://" not in value:
        value = "http://" + value
    netloc = urlparse(value).netloc
    return netloc.split(":")[0].removeprefix("www.")


def registrable(domain: str) -> str:
    """Approximation du domaine enregistrable (2 derniers labels, 3 si ccTLD type .qc.ca).
    Suffisant pour un projet pédagogique ; en prod on utiliserait la Public Suffix List."""
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-1] == "ca" and parts[-2] in {"gc", "qc", "on", "bc", "ab"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _match_any(patterns: list[str], text: str) -> list[str]:
    found = []
    for p in patterns:
        m = re.search(p, text, re.IGNORECASE)
        if m:
            found.append(m.group(0))
    return found


# ---------------------------------------------------------------------------
# Règles (fonctions pures)
# ---------------------------------------------------------------------------

def rule_urgency(email: Email) -> Signal | None:
    """R01 — Pression temporelle : tactique n°1 du phishing (empêcher la réflexion)."""
    text = f"{email.subject}\n{email.body_text}"
    hits = _match_any(URGENCY_PATTERNS, text)
    if not hits:
        return None
    weight = 15 if len(hits) == 1 else 22
    return Signal(
        rule_id="R01_URGENCY",
        name="Langage d'urgence",
        weight=weight,
        evidence="; ".join(f"« {h} »" for h in hits[:3]),
        description="Le message crée une pression temporelle pour court-circuiter le jugement.",
    )


def rule_domain_mismatch(email: Email) -> Signal | None:
    """R02 — Le texte d'un lien affiche un domaine différent du domaine réel de l'URL."""
    for text, url in zip(email.link_texts, email.links):
        shown = extract_domain(text) if ("." in text and " " not in text.strip()) else ""
        real = extract_domain(url)
        if shown and real and registrable(shown) != registrable(real):
            return Signal(
                rule_id="R02_LINK_MISMATCH",
                name="Domaine affiché ≠ domaine réel",
                weight=30,
                evidence=f"Texte affiché « {text.strip()} » → URL réelle « {real} »",
                description="Le lien prétend mener vers un site mais pointe ailleurs : "
                            "technique de dissimulation classique.",
            )
    return None


def rule_typosquatting(email: Email) -> Signal | None:
    """R03 — Domaine à distance de Levenshtein 1-2 d'un domaine connu (desjardlns.com)."""
    candidates = [extract_domain(email.sender)] + [extract_domain(u) for u in email.links]
    for cand in filter(None, candidates):
        cand_reg = registrable(cand)
        if cand_reg in KNOWN_DOMAINS:
            continue  # domaine légitime exact
        for known in KNOWN_DOMAINS:
            base_c, base_k = cand_reg.rsplit(".", 1)[0], known.rsplit(".", 1)[0]
            if levenshtein(base_c, base_k) in (1, 2) and len(base_k) >= 4:
                return Signal(
                    rule_id="R03_TYPOSQUATTING",
                    name="Typosquatting",
                    weight=35,
                    evidence=f"« {cand_reg} » imite « {known} » "
                             f"(distance de Levenshtein = {levenshtein(base_c, base_k)})",
                    description="Le domaine imite un domaine légitime à une ou deux lettres près.",
                )
    return None


def rule_sensitive_request(email: Email) -> Signal | None:
    """R04 — Demande d'informations sensibles (mot de passe, NIP, carte, NAS…)."""
    hits = _match_any(SENSITIVE_PATTERNS, email.body_text)
    if not hits:
        return None
    return Signal(
        rule_id="R04_SENSITIVE_INFO",
        name="Demande d'informations sensibles",
        weight=25,
        evidence="; ".join(f"« {h} »" for h in hits[:3]),
        description="Aucune organisation légitime ne demande ces informations par courriel.",
    )


def rule_incoherence(email: Email) -> Signal | None:
    """R05 — Formulations génériques/maladroites typiques des campagnes de masse."""
    text = f"{email.subject}\n{email.body_text}"
    hits = _match_any(INCOHERENCE_PATTERNS, text)
    if not hits:
        return None
    return Signal(
        rule_id="R05_INCOHERENCE",
        name="Formulations génériques suspectes",
        weight=10,
        evidence="; ".join(f"« {h} »" for h in hits[:3]),
        description="Salutations génériques et tournures stéréotypées des campagnes de masse.",
    )


def rule_suspicious_attachment(email: Email) -> Signal | None:
    """R06 — Pièce jointe exécutable ou à macros, éventuellement à double extension."""
    for name in email.attachments:
        low = name.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if low.endswith(ext):
                double = len(re.findall(r"\.(pdf|doc|xls|jpg|png)\.", low)) > 0
                return Signal(
                    rule_id="R06_ATTACHMENT",
                    name="Pièce jointe dangereuse",
                    weight=30 if double else 25,
                    evidence=f"Fichier « {name} »" + (" (double extension)" if double else ""),
                    description="Extension exécutable ou à macros : vecteur d'infection courant.",
                )
    return None


def rule_shortened_link(email: Email) -> Signal | None:
    """R07 — Lien raccourci masquant la destination réelle."""
    for url in email.links:
        if extract_domain(url) in URL_SHORTENERS:
            return Signal(
                rule_id="R07_SHORTENER",
                name="Lien raccourci",
                weight=15,
                evidence=f"URL « {url} »",
                description="Un raccourcisseur masque la destination réelle du lien.",
            )
    return None


def rule_replyto_mismatch(email: Email) -> Signal | None:
    """R08 — Reply-To vers un domaine différent de l'expéditeur (détournement de réponse)."""
    if not email.reply_to:
        return None
    d_from, d_reply = extract_domain(email.sender), extract_domain(email.reply_to)
    if d_from and d_reply and registrable(d_from) != registrable(d_reply):
        return Signal(
            rule_id="R08_REPLYTO",
            name="Reply-To divergent",
            weight=20,
            evidence=f"From « {d_from} » mais Reply-To « {d_reply} »",
            description="Les réponses sont détournées vers une autre boîte que l'expéditeur affiché.",
        )
    return None


def rule_display_name_spoof(email: Email) -> Signal | None:
    """R09 — Nom affiché évoquant une marque connue, mais expéditeur sur un autre domaine
    (souvent un webmail gratuit)."""
    display = email.sender_display.lower()
    if not display:
        return None
    sender_reg = registrable(extract_domain(email.sender))
    sender_brand = sender_reg.rsplit(".", 1)[0]  # "amazon.ca" -> "amazon"
    for known in KNOWN_DOMAINS:
        brand = known.rsplit(".", 1)[0]
        # Un domaine portant lui-même la marque (amazon.ca vs amazon.com)
        # n'est pas une usurpation : on exige un domaine étranger à la marque.
        if len(brand) >= 4 and brand in display and sender_brand != brand:
            return Signal(
                rule_id="R09_DISPLAY_SPOOF",
                name="Usurpation du nom affiché",
                weight=25,
                evidence=f"Nom affiché « {email.sender_display} » mais expéditeur « {sender_reg} »",
                description="Le nom affiché imite une organisation sans provenir de son domaine.",
            )
    return None


def rule_ip_or_odd_url(email: Email) -> Signal | None:
    """R10 — URL vers une adresse IP brute ou un TLD notoirement abusé."""
    odd_tlds = (".xyz", ".top", ".click", ".zip", ".mov", ".tk", ".gq", ".ml", ".cam")
    for url in email.links:
        dom = extract_domain(url)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", dom):
            return Signal(
                rule_id="R10_ODD_URL",
                name="URL anormale",
                weight=25,
                evidence=f"Lien vers une adresse IP brute : « {url} »",
                description="Les services légitimes n'utilisent pas d'IP brute dans leurs liens.",
            )
        if dom.endswith(odd_tlds):
            return Signal(
                rule_id="R10_ODD_URL",
                name="URL anormale",
                weight=15,
                evidence=f"TLD fréquemment abusé : « {dom} »",
                description="Ce TLD à bas coût est surreprésenté dans les campagnes malveillantes.",
            )
    return None


ALL_RULES = [
    rule_urgency,
    rule_domain_mismatch,
    rule_typosquatting,
    rule_sensitive_request,
    rule_incoherence,
    rule_suspicious_attachment,
    rule_shortened_link,
    rule_replyto_mismatch,
    rule_display_name_spoof,
    rule_ip_or_odd_url,
]


def run_rules(email: Email) -> tuple[list[Signal], int]:
    """Exécute toutes les règles. Retourne (signaux, score plafonné à 100)."""
    signals = [s for rule in ALL_RULES if (s := rule(email)) is not None]
    score = min(100, sum(s.weight for s in signals))
    return signals, score


def parse_body_links(body_html_or_text: str) -> tuple[list[str], list[str]]:
    """Extrait (urls, textes d'ancre) d'un corps HTML simple ou texte brut."""
    links, texts = [], []
    for m in re.finditer(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                         body_html_or_text, re.IGNORECASE | re.DOTALL):
        links.append(m.group(1))
        texts.append(re.sub(r"<[^>]+>", "", m.group(2)).strip())
    for url in _URL_RE.findall(re.sub(r"<a[^>]+>.*?</a>", "", body_html_or_text,
                                      flags=re.IGNORECASE | re.DOTALL)):
        links.append(url)
        texts.append("")
    return links, texts
