"""PDF des rapports, produits par le serveur (ADR-0036) : rapport périodique, rapport d'incident, point de situation,
rapport d'analyse. Mise en page simple et sobre, une colonne, en-tête avec le marquage TLP et pied de page numéroté.

Sécurité : tout texte est échappé avant d'entrer dans le mini-langage de balisage de reportlab ; le HTML des tickets
(déjà assaini côté serveur) est relu par html.parser et réduit à des paragraphes, listes, gras, italique et code. Aucune
ressource externe n'est chargée (ni image distante, ni police distante).
"""
from __future__ import annotations

import io
import os
from datetime import datetime
from html import escape
from html.parser import HTMLParser

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

# Police : DejaVu si elle est installée (image Docker : paquet fonts-dejavu-core), pour écrire tous les caractères
# d'une alerte ; sinon les polices de base du PDF, et les caractères qu'elles n'ont pas sont remplacés par « ? ».
FONT_DIRS = [d for d in (os.environ.get("KERYX_PDF_FONT_DIR"), "/usr/share/fonts/truetype/dejavu",
                         "/usr/share/fonts/TTF", "/usr/share/fonts/dejavu") if d]
_FONTS: dict[str, str] | None = None


def fonts() -> dict[str, str]:
    global _FONTS
    if _FONTS is None:
        for d in FONT_DIRS:
            files = {k: os.path.join(d, f) for k, f in (("regular", "DejaVuSans.ttf"), ("bold", "DejaVuSans-Bold.ttf"),
                                                         ("italic", "DejaVuSans-Oblique.ttf"), ("mono", "DejaVuSansMono.ttf"))}
            if all(os.path.isfile(p) for p in files.values()):
                for k, p in files.items():
                    pdfmetrics.registerFont(TTFont(f"Keryx-{k}", p))
                pdfmetrics.registerFontFamily("Keryx-regular", normal="Keryx-regular", bold="Keryx-bold",
                                              italic="Keryx-italic", boldItalic="Keryx-bold")
                _FONTS = {"regular": "Keryx-regular", "bold": "Keryx-bold", "italic": "Keryx-italic",
                          "mono": "Keryx-mono", "unicode": "oui"}
                break
        else:
            _FONTS = {"regular": "Helvetica", "bold": "Helvetica-Bold", "italic": "Helvetica-Oblique", "mono": "Courier",
                      "unicode": ""}
    return _FONTS


def txt(value) -> str:
    """Texte sûr pour le balisage de reportlab : échappé, et ramené au jeu de caractères des polices de base si
    aucune police Unicode n'est installée."""
    s = "" if value is None else str(value)
    if not fonts()["unicode"]:
        s = s.encode("cp1252", "replace").decode("cp1252")
    return escape(s, quote=False)


def fmt_date(value: str | None) -> str:
    """Date RFC 3339 de l'API en « 28/11/2026 14:05 UTC » (les rapports restent en UTC, comme l'interface de l'équipe)."""
    if not value:
        return "—"
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    return d.strftime("%d/%m/%Y %H:%M UTC")


INK, MUTED, LINE, SOFT = colors.HexColor("#16191F"), colors.HexColor("#5B6472"), colors.HexColor("#D5DAE1"), colors.HexColor("#F1F3F6")


class _Html(HTMLParser):
    """HTML assaini des tickets réduit à des blocs (paragraphes, titres, listes, code) en balisage reportlab."""
    BLOCKS = {"p", "div", "h1", "h2", "h3", "h4", "li", "pre", "blockquote", "tr"}

    def __init__(self, mono: str):
        super().__init__(convert_charrefs=True)
        self.mono, self.blocks, self.cur, self.kind, self.pre = mono, [], [], "p", 0

    def flush(self):
        text = "".join(self.cur).strip()
        if text:
            self.blocks.append((self.kind, text))
        self.cur, self.kind = [], "p"

    def handle_starttag(self, tag, attrs):
        if tag in self.BLOCKS:
            self.flush()
            self.kind = {"h1": "h", "h2": "h", "h3": "h", "h4": "h", "li": "li", "pre": "pre"}.get(tag, "p")
            self.pre += tag == "pre"
        elif tag in ("b", "strong"):
            self.cur.append("<b>")
        elif tag in ("i", "em"):
            self.cur.append("<i>")
        elif tag == "code":
            self.cur.append(f'<font name="{self.mono}">')
        elif tag == "br":
            self.cur.append("<br/>")
        elif tag == "img":
            self.cur.append("[image]")
        elif tag in ("td", "th"):
            self.cur.append(" | " if self.cur else "")

    def handle_endtag(self, tag):
        if tag in self.BLOCKS:
            self.pre -= tag == "pre"
            self.flush()
        elif tag in ("b", "strong"):
            self.cur.append("</b>")
        elif tag in ("i", "em"):
            self.cur.append("</i>")
        elif tag == "code":
            self.cur.append("</font>")

    def handle_data(self, data):
        t = txt(data)
        self.cur.append(t.replace("\n", "<br/>") if self.pre else t)

    def close(self):
        super().close()
        self.flush()
        return self.blocks


def _balance(markup: str) -> str:
    """Referme les balises inline laissées ouvertes par un HTML tronqué (sinon reportlab refuse le paragraphe)."""
    for tag, close in (("<b>", "</b>"), ("<i>", "</i>")):
        markup += close * max(0, markup.count(tag) - markup.count(close))
    markup += "</font>" * max(0, markup.count("<font ") - markup.count("</font>"))
    return markup


class Pdf:
    def __init__(self, titre: str, sous_titre: str = "", tlp: str = "", genere_le: str = ""):
        f = fonts()
        self.f, self.titre, self.tlp, self.genere_le = f, titre, tlp, genere_le
        self.story: list = []
        base = dict(fontName=f["regular"], fontSize=9.5, leading=13, textColor=INK, alignment=TA_LEFT)
        self.st = {
            "p": ParagraphStyle("p", **base, spaceAfter=4),
            "muted": ParagraphStyle("muted", **{**base, "textColor": MUTED, "fontSize": 8.5, "leading": 11}, spaceAfter=4),
            "h1": ParagraphStyle("h1", **{**base, "fontName": f["bold"], "fontSize": 16, "leading": 20}, spaceAfter=4),
            "h2": ParagraphStyle("h2", **{**base, "fontName": f["bold"], "fontSize": 12, "leading": 15}, spaceBefore=10, spaceAfter=4),
            "h3": ParagraphStyle("h3", **{**base, "fontName": f["bold"], "fontSize": 10, "leading": 13}, spaceBefore=6, spaceAfter=2),
            "cell": ParagraphStyle("cell", **{**base, "fontSize": 8.5, "leading": 11}),
            "cellb": ParagraphStyle("cellb", **{**base, "fontName": f["bold"], "fontSize": 8, "leading": 10, "textColor": MUTED}),
            "pre": ParagraphStyle("pre", **{**base, "fontName": f["mono"], "fontSize": 8, "leading": 10.5}, spaceAfter=4),
        }
        self.h1(titre)
        if sous_titre:
            self.p(sous_titre, muted=True)

    # ------------------------------------------------------------------ éléments
    def h1(self, t):
        self.story.append(Paragraph(txt(t), self.st["h1"]))

    def h2(self, t):
        self.story.append(Paragraph(txt(t), self.st["h2"]))

    def h3(self, t):
        self.story.append(Paragraph(txt(t), self.st["h3"]))

    def p(self, t, muted: bool = False):
        if t in (None, ""):
            t = "Non renseigné"
            muted = True
        self.story.append(Paragraph(txt(t).replace("\n", "<br/>"), self.st["muted" if muted else "p"]))

    def kv(self, pairs):
        rows = [[Paragraph(txt(k), self.st["cellb"]), Paragraph(txt(v if v not in (None, "") else "—").replace("\n", "<br/>"), self.st["cell"])]
                for k, v in pairs]
        if rows:
            t = Table(rows, colWidths=[55 * mm, None], hAlign="LEFT")
            t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                                   ("TOPPADDING", (0, 0), (-1, -1), 2), ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE)]))
            self.story.append(t)

    def table(self, headers, rows, widths=None, vide: str = "Aucune donnée."):
        if not rows:
            self.p(vide, muted=True)
            return
        data = [[Paragraph(txt(h), self.st["cellb"]) for h in headers]]
        data += [[Paragraph(txt(c if c not in (None, "") else "—"), self.st["cell"]) for c in r] for r in rows]
        widths = widths or [1] * len(headers)       # des paragraphes en cellule exigent des largeurs connues
        w = [180 * mm * x / sum(widths) for x in widths]
        t = Table(data, colWidths=w, repeatRows=1, hAlign="LEFT")
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BACKGROUND", (0, 0), (-1, 0), SOFT),
                               ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE), ("TOPPADDING", (0, 0), (-1, -1), 2),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        self.story.append(t)

    def bullets(self, items):
        if not items:
            return
        self.story.append(ListFlowable([ListItem(Paragraph(txt(i), self.st["p"]), leftIndent=10) for i in items],
                                       bulletType="bullet", start="•", leftIndent=10, bulletFontName=self.f["regular"]))

    def html(self, fragment: str | None):
        if not fragment:
            self.p(None)
            return
        parser = _Html(self.f["mono"])
        parser.feed(fragment)
        items: list = []
        for kind, markup in parser.close():
            markup = _balance(markup)
            if kind == "li":
                items.append(markup)
                continue
            if items:
                self.story.append(ListFlowable([ListItem(Paragraph(m, self.st["p"]), leftIndent=10) for m in items],
                                               bulletType="bullet", start="•", leftIndent=10, bulletFontName=self.f["regular"]))
                items = []
            style = {"h": "h3", "pre": "pre"}.get(kind, "p")
            self.story.append(Paragraph(markup, self.st[style]))
        if items:
            self.story.append(ListFlowable([ListItem(Paragraph(m, self.st["p"]), leftIndent=10) for m in items],
                                           bulletType="bullet", start="•", leftIndent=10, bulletFontName=self.f["regular"]))

    def bloc(self, *flowables):
        self.story.append(KeepTogether(list(flowables)))

    def espace(self, h: float = 4):
        self.story.append(Spacer(1, h * mm))

    # ------------------------------------------------------------------ rendu
    def _page(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        canvas.setFont(self.f["bold"], 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(15 * mm, h - 10 * mm, txt_canvas(f"Keryx · {self.titre}"))
        if self.tlp:
            canvas.drawRightString(w - 15 * mm, h - 10 * mm, txt_canvas(self.tlp))
        canvas.setFont(self.f["regular"], 7.5)
        canvas.drawString(15 * mm, 9 * mm, txt_canvas(f"Généré le {self.genere_le}" if self.genere_le else ""))
        canvas.drawRightString(w - 15 * mm, 9 * mm, f"{doc.page}")
        canvas.restoreState()

    def render(self) -> bytes:
        buf = io.BytesIO()
        from reportlab import rl_config
        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm,
                                bottomMargin=15 * mm, title=self.titre, author="Keryx", creator="Keryx",
                                pageCompression=rl_config.pageCompression)
        doc.build(self.story, onFirstPage=self._page, onLaterPages=self._page)
        return buf.getvalue()


def txt_canvas(s: str) -> str:
    """Texte dessiné directement sur la page (en-tête, pied) : pas de balisage, seulement le jeu de caractères."""
    return s if fonts()["unicode"] else s.encode("cp1252", "replace").decode("cp1252")
