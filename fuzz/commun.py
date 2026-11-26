"""Propriétés de sécurité vérifiées par les cibles de fuzzing (voir fuzz/README.md).

Un HTML produit par Keryx, quelle que soit l'entrée, ne contient que les balises et attributs de la liste blanche de
keryx/sanitize.py, aucun gestionnaire d'événement, aucune adresse hors https, mailto ou relative, et aucune image
hors du contenu d'une pièce déposée.
"""
from __future__ import annotations

from html.parser import HTMLParser

from keryx.sanitize import _EMBEDDED_IMAGE, ALLOWED_ATTRIBUTES, ALLOWED_TAGS

SCHEMAS_PERMIS = ("https:", "mailto:")


class Defaut(AssertionError):
    """Propriété de sécurité violée : le fuzzer s'arrête et garde l'entrée qui la provoque."""


def _schema(adresse: str) -> str | None:
    """Schéma d'une adresse tel que le lit un navigateur (blancs et caractères de contrôle ignorés), ou None."""
    propre = "".join(c for c in adresse if c > " " and c != "\x7f").lower()
    deux_points = propre.find(":")
    if deux_points == -1 or any(c in propre[:deux_points] for c in "/?#"):
        return None
    return propre[: deux_points + 1]


class _Lecteur(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)

    def handle_starttag(self, tag, attrs):
        if tag not in ALLOWED_TAGS:
            raise Defaut(f"balise hors liste blanche : <{tag}>")
        for nom, valeur in attrs:
            if nom.startswith("on"):
                raise Defaut(f"gestionnaire d'événement : <{tag} {nom}>")
            if nom not in ALLOWED_ATTRIBUTES.get(tag, set()) and not (tag == "a" and nom == "rel"):
                raise Defaut(f"attribut hors liste blanche : <{tag} {nom}>")
            valeur = valeur or ""
            if tag == "a" and nom == "href":
                schema = _schema(valeur)
                if schema is not None and schema not in SCHEMAS_PERMIS:
                    raise Defaut(f"adresse de schéma interdit : {valeur[:80]!r}")
            if tag == "img" and nom == "src" and not _EMBEDDED_IMAGE.match(valeur):
                raise Defaut(f"image hors des pièces déposées : {valeur[:80]!r}")

    handle_startendtag = handle_starttag


def verifier_html(sortie: str) -> None:
    lecteur = _Lecteur()
    lecteur.feed(sortie)
    lecteur.close()
