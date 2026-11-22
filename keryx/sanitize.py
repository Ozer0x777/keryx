"""Assainissement du HTML des tickets (liste blanche, côté serveur).

[ASVS 5.0 V1 encodage/assainissement] contre le XSS stocké : un ticket est lu par plusieurs
rôles, y compris le client. Les données issues de Wazuh sont échappées avant d'être mises en forme.
"""
from __future__ import annotations

import html
import re

import nh3

# Seule adresse admise pour une image : le contenu d'une pièce déposée dans Keryx, sans paramètre. Une adresse relative
# quelconque ferait appeler, par le navigateur de qui lit le ticket, n'importe quelle route en lecture de l'API.
_EMBEDDED_IMAGE = re.compile(r"^/api/v1/attachments/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/content$")


def _attribute_filter(tag: str, attribute: str, value: str) -> str | None:
    if tag == "img" and attribute == "src":
        return value if _EMBEDDED_IMAGE.match(value) else None
    return value

ALLOWED_TAGS = {
    "p", "br", "strong", "em", "b", "i", "u", "s", "code", "pre", "blockquote",
    "h2", "h3", "h4", "ul", "ol", "li", "a", "img",
    "table", "thead", "tbody", "tr", "th", "td",
}
ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "img": {"src", "alt"},
    "th": {"scope"},
}


def clean_html(value: str) -> str:
    return nh3.clean(
        value or "",
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes={"https", "mailto"},
        attribute_filter=_attribute_filter,
        link_rel="noopener noreferrer",
        strip_comments=True,
    )


def esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)
