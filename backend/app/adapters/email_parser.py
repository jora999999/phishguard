"""Adapter d'entrée : convertit .eml (RFC 822) ou JSON en entité Email du domaine."""
from __future__ import annotations

import email as email_lib
import email.policy
import re

from ..domain.models import Email
from ..domain.rules import parse_body_links

_ADDR_RE = re.compile(r'^\s*"?([^"<]*)"?\s*<([^>]+)>\s*$')


def _split_display(value: str) -> tuple[str, str]:
    """'"Desjardins" <a@b.com>' -> ("Desjardins", "a@b.com")."""
    m = _ADDR_RE.match(value or "")
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return "", (value or "").strip()


def from_json(payload: dict) -> Email:
    """Construit un Email depuis le JSON de l'API/extension/dataset."""
    body = payload.get("body_text", "") or ""
    links = payload.get("links")
    link_texts = payload.get("link_texts")
    if links is None:  # extraire depuis le corps si non fournis
        links, link_texts = parse_body_links(body)
    display, sender = _split_display(payload.get("sender", ""))
    return Email(
        subject=payload.get("subject", ""),
        sender=sender,
        sender_display=payload.get("sender_display") or display,
        reply_to=payload.get("reply_to", "") or "",
        body_text=re.sub(r"<[^>]+>", " ", body),  # corps nettoyé du HTML
        links=list(links or []),
        link_texts=list(link_texts or [""] * len(links or [])),
        attachments=list(payload.get("attachments", []) or []),
    )


def from_eml(raw: bytes) -> Email:
    """Construit un Email depuis un fichier .eml brut (mode batch)."""
    msg = email_lib.message_from_bytes(raw, policy=email.policy.default)
    body_parts, attachments = [], []
    for part in msg.walk():
        fname = part.get_filename()
        if fname:
            attachments.append(fname)
        elif part.get_content_type() in ("text/plain", "text/html"):
            try:
                body_parts.append(part.get_content())
            except Exception:
                pass
    body = "\n".join(body_parts)
    links, link_texts = parse_body_links(body)
    display, sender = _split_display(str(msg.get("From", "")))
    return Email(
        subject=str(msg.get("Subject", "")),
        sender=sender,
        sender_display=display,
        reply_to=str(msg.get("Reply-To", "") or ""),
        body_text=re.sub(r"<[^>]+>", " ", body),
        links=links,
        link_texts=link_texts,
        attachments=attachments,
    )
