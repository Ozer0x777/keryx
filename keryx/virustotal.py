"""Recherche d'une empreinte de fichier sur VirusTotal (API v3). DÉROGATION à « aucun service externe » : ADR-0022.

[PRIS IV.3.q codes malveillants ; PDIS IV.2.1.q qualification ; PRIS VI.5.3.d registre des actions ; ISO/IEC 27037
(chaîne de possession) ; PDIS IV.3.8.g cloisonnement ; ISO/IEC 27002:2022 8.24 (secrets, via ADR-0006) ; RFC 3339]
Aucune exigence de la matrice du projet n'impose de consulter un service de réputation : la fonction est une demande
du projet (22/11/2026), rattachée ici à la qualification et au traitement des codes malveillants.

Ce qui sort de Keryx, et rien d'autre : UNE empreinte (SHA-256 ou SHA-1, 64 ou 40 caractères hexadécimaux), la clé
d'API de l'utilisateur qui lance la recherche (en-tête `x-apikey`), et l'adresse IP de sortie du serveur. Jamais un
fichier, jamais un nom de fichier, de client, de ticket ou d'équipement.

Appel sortant borné :
- hôte FIXE (`www.virustotal.com`) : aucune adresse n'est saisie par un utilisateur, donc pas de requête forgée côté
  serveur ; le seul remplacement possible est un réglage d'instance réservé aux essais (`KERYX_VIRUSTOTAL_URL`) ;
- HTTPS (TLS 1.2 au moins), certificat vérifié contre le magasin d'autorités du système, contrôle non désactivable ;
  aucune redirection suivie, aucun mandataire d'environnement (`trust_env=False`) ; un mandataire explicite est
  possible (`KERYX_VIRUSTOTAL_PROXY`) ;
- délai court (3 s pour se connecter, 8 s pour l'ensemble), réponse bornée à 4 Mio, JSON seulement ;
- tout texte de la réponse est une donnée non fiable : ramené à du texte pur et borné (`clean_text`).

Ce module contient le client HTTP isolé (`Client`) : l'envoi d'un fichier, s'il est décidé un jour, y serait une
seconde méthode, avec les conditions décrites dans ADR-0022 (accord du client, TLP, taille). Il n'existe pas aujourd'hui.
Ce module n'a été essayé que contre le faux serveur des tests (tests/fake_virustotal.py), jamais contre le vrai
VirusTotal.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import ssl
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx

from .ids import rfc3339
from .wazuh_context import clean_text

log = logging.getLogger("keryx.virustotal")

OFFICIAL_URL = "https://www.virustotal.com"
GUI_FILE_URL = "https://www.virustotal.com/gui/file/"     # lien construit par Keryx, jamais lu dans une réponse
CONNECT_TIMEOUT_S = 3.0
READ_TIMEOUT_S = 5.0
TOTAL_TIMEOUT_S = 8.0
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_ENGINE_NAMES = 8
MAX_ALERTS = 25               # alertes brutes d'un ticket parcourues pour y chercher des empreintes
MAX_ALERT_NODES = 2000        # valeurs visitées par alerte
MAX_CANDIDATES = 40           # empreintes d'alertes proposées par ticket

# MD5 n'est pas accepté : collisions praticables (deux fichiers différents, la même empreinte), donc un rapport
# VirusTotal obtenu par MD5 peut décrire un autre fichier que celui du ticket. Wazuh fournit SHA-1 et SHA-256.
HASH_PATTERNS = {"sha256": re.compile(r"^[0-9a-f]{64}$"), "sha1": re.compile(r"^[0-9a-f]{40}$")}
HASH_PATTERN = r"^(?:[0-9a-f]{64}|[0-9a-f]{40})$"
_HASH_IN_TEXT = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40})(?![0-9A-Fa-f])")
# Forme d'une clé d'API : lettres et chiffres, longueur bornée. La forme exacte des clés émises par VirusTotal n'a pas
# été vérifiée sur le service : la borne est volontairement large.
_API_KEY = re.compile(r"^[A-Za-z0-9]{32,128}$")
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")
_RECEIVED = re.compile(r"^empreinte reçue ([0-9a-f]{64})$")


class ConfigError(ValueError):
    """Réglage refusé : le message est destiné à l'exploitant ou à l'utilisateur (jamais de secret dedans)."""


class VirusTotalError(Exception):
    """Échec d'une recherche. `message` est montré à l'analyste, `reason` va dans l'audit et les journaux.
    Ni l'un ni l'autre ne contient la clé d'API, un en-tête ou le corps de la réponse."""

    def __init__(self, status: int, message: str, reason: str):
        super().__init__(message)
        self.status, self.message, self.reason = status, message, reason


# ---------------------------------------------------------------- validations
def hash_kind(value) -> str | None:
    """« sha256 », « sha1 », ou None si la valeur n'est pas une empreinte acceptée (minuscules, longueur exacte)."""
    if not isinstance(value, str):
        return None
    for kind, pattern in HASH_PATTERNS.items():
        if pattern.match(value):
            return kind
    return None


def validate_api_key(value) -> str:
    """Clé d'API saisie par l'utilisateur. Le message d'erreur ne recopie jamais la saisie."""
    v = value.strip() if isinstance(value, str) else ""
    if not _API_KEY.match(v):
        raise ConfigError("Clé d'API VirusTotal invalide : 32 à 128 lettres et chiffres, sans espace ni autre caractère.")
    return v


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost" or host.endswith(".localhost")


def _origin(value: str, what: str) -> tuple[str, str, int | None]:
    """(schéma, hôte, port) d'une adresse « schéma://hôte[:port] » sans identifiants, chemin, paramètres ni fragment."""
    v = value.strip()
    if len(v) > 300 or any(ord(c) <= 32 or ord(c) == 127 for c in v) or "\\" in v:
        raise ConfigError(f"{what} invalide.")
    try:
        u = urlsplit(v)
        port = u.port
    except ValueError as exc:
        raise ConfigError(f"{what} invalide.") from exc
    if "@" in u.netloc:
        raise ConfigError(f"{what} : pas d'identifiants dans l'adresse.")
    if u.path not in ("", "/") or u.query or u.fragment or "?" in v or "#" in v:
        raise ConfigError(f"{what} : ni chemin, ni paramètres, ni fragment (schéma://hôte[:port]).")
    host = (u.hostname or "").rstrip(".").lower()
    if not host or (port is not None and not 1 <= port <= 65535):
        raise ConfigError(f"{what} invalide.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOSTNAME.match(host):
            raise ConfigError(f"{what} : nom d'hôte invalide.") from None
    return u.scheme, host, port


def _join(scheme: str, host: str, port: int | None) -> str:
    host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host}{'' if port is None else f':{port}'}"


def parse_base_url(value: str | None, allow_loopback: bool = False) -> str:
    """Adresse de base de l'API. Vide : l'hôte officiel. Sinon (essais) : HTTPS, ou HTTP en clair vers la boucle
    locale si la dérogation `KERYX_VIRUSTOTAL_ALLOW_LOOPBACK` est posée. Jamais réglable par un utilisateur."""
    if not value or not value.strip():
        return OFFICIAL_URL
    scheme, host, port = _origin(value, "KERYX_VIRUSTOTAL_URL")
    if scheme == "http":
        if not (allow_loopback and _is_loopback(host)):
            raise ConfigError("KERYX_VIRUSTOTAL_URL doit être en HTTPS (HTTP en clair : boucle locale seulement, avec "
                              "KERYX_VIRUSTOTAL_ALLOW_LOOPBACK, pour les essais).")
    elif scheme != "https":
        raise ConfigError("KERYX_VIRUSTOTAL_URL doit commencer par https://.")
    return _join(scheme, host, port)


def parse_proxy(value: str | None) -> str | None:
    """Mandataire explicite de cette sortie : http://hôte:port (ou https://), sans identifiants."""
    if not value or not value.strip():
        return None
    scheme, host, port = _origin(value, "KERYX_VIRUSTOTAL_PROXY")
    if scheme not in ("http", "https"):
        raise ConfigError("KERYX_VIRUSTOTAL_PROXY doit commencer par http:// ou https://.")
    return _join(scheme, host, port)


def gui_url(digest: str) -> str:
    """Adresse de la fiche du fichier sur le site de VirusTotal : hôte officiel et empreinte validée, rien d'autre."""
    if hash_kind(digest) is None:
        raise ValueError("empreinte invalide")
    return GUI_FILE_URL + digest


def received_hash(custody_reason: str | None) -> str | None:
    """Empreinte du fichier tel qu'il a été REÇU, lue dans le motif de l'événement de dépôt (« empreinte reçue … »,
    écrit par le serveur quand une image est ré-encodée). None si le dépôt n'a rien transformé."""
    m = _RECEIVED.match(custody_reason or "")
    return m.group(1) if m else None


# ---------------------------------------------------------------- résumé d'une réponse (donnée non fiable)
def _count(value) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100_000 else 0


def _epoch(value) -> str | None:
    """Date Unix (secondes) rendue en UTC, RFC 3339 ; None hors de 1970-2100 ou si ce n'est pas un entier."""
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value < 4_102_444_800:
        return None
    return rfc3339(datetime.fromtimestamp(value, tz=timezone.utc))


def summarize(attributes: dict) -> dict:
    """Résumé borné de l'objet « fichier » de VirusTotal : compteurs entiers, dates UTC, textes purs et courts.
    Aucune adresse n'est reprise de la réponse ; aucune structure libre n'est conservée."""
    def d(v):
        return v if isinstance(v, dict) else {}
    stats = d(attributes.get("last_analysis_stats"))
    counts = {k: _count(stats.get(k)) for k in ("malicious", "suspicious", "harmless", "undetected")}
    total = sum(_count(v) for v in list(stats.values())[:20])
    names = []
    results = d(attributes.get("last_analysis_results"))
    for wanted in ("malicious", "suspicious"):
        for engine in sorted((k for k in list(results)[:400] if isinstance(k, str)), key=str.lower):
            r = d(results[engine])
            if r.get("category") == wanted and r.get("result") and len(names) < MAX_ENGINE_NAMES:
                names.append({"engine": clean_text(engine, 60), "result": clean_text(r.get("result"), 120)})
    size = attributes.get("size")
    sha256 = attributes.get("sha256")
    return {
        "stats": {**counts, "total": total},
        "last_analysis_date": _epoch(attributes.get("last_analysis_date")),
        "first_submission_date": _epoch(attributes.get("first_submission_date")),
        "name": clean_text(attributes.get("meaningful_name"), 200),
        "type": clean_text(attributes.get("type_description"), 100),
        "size": size if isinstance(size, int) and not isinstance(size, bool) and 0 <= size < 2**50 else None,
        "threat_label": clean_text(d(attributes.get("popular_threat_classification")).get("suggested_threat_label"), 100),
        "engine_names": names,
        # SHA-256 annoncé par VirusTotal (utile après une recherche par SHA-1) : repris seulement s'il en a la forme.
        "sha256": sha256 if hash_kind(sha256) == "sha256" else None,
    }


# ---------------------------------------------------------------- empreintes présentes dans une alerte Wazuh
def extract_alert_hashes(payload) -> list[dict]:
    """Empreintes SHA-256 et SHA-1 d'une alerte brute : contrôle d'intégrité (`syscheck.sha256_after`, `sha1_after`…)
    et champs `data.*` qui en ont la forme (dont les listes « SHA1=…,SHA256=… » de Sysmon). Parcours défensif : seuls
    `syscheck` et `data` sont lus, profondeur, nombre de valeurs et longueur des textes bornés. Renvoie une liste de
    {hash, hash_type, field, file}, sans doublon, dans l'ordre de lecture."""
    if not isinstance(payload, dict):
        return []
    found: dict[str, dict] = {}
    visited = 0
    syscheck = payload.get("syscheck") if isinstance(payload.get("syscheck"), dict) else {}
    file_path = clean_text(syscheck.get("path"), 300)

    def walk(value, path: str, depth: int) -> None:
        nonlocal visited
        visited += 1
        if visited > MAX_ALERT_NODES or depth > 8 or len(found) >= MAX_CANDIDATES:
            return
        if isinstance(value, dict):
            for k in list(value)[:200]:
                key = re.sub(r"[^A-Za-z0-9_.@-]", "_", str(k))[:60]
                walk(value[k], f"{path}.{key}", depth + 1)
        elif isinstance(value, list):
            for item in value[:50]:
                walk(item, path, depth + 1)
        elif isinstance(value, str) and 40 <= len(value) <= 4096:
            for match in _HASH_IN_TEXT.findall(value)[:8]:
                digest = match.lower()
                if digest not in found and len(found) < MAX_CANDIDATES:
                    found[digest] = {"hash": digest, "hash_type": hash_kind(digest), "field": path[:120],
                                     "file": file_path if path.startswith("syscheck.") else ""}

    for root in ("syscheck", "data"):
        if isinstance(payload.get(root), dict):
            walk(payload[root], root, 0)
    return list(found.values())


# ---------------------------------------------------------------- client HTTP isolé
def _tls_context() -> ssl.SSLContext:
    """Autorités du système d'exploitation, nom d'hôte vérifié. Aucun réglage ne retire ce contrôle ni n'ajoute une
    autorité : la clé d'un utilisateur ne part jamais vers un serveur dont le certificat n'est pas reconnu."""
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


@dataclass(frozen=True)
class Report:
    status: str                         # trouve | inconnu
    summary: dict = field(default_factory=dict)


class Client:
    """Client de l'API VirusTotal v3. Une seule opération : lire le rapport d'un fichier par son empreinte.
    Un client par appel, aucune connexion ni clé gardée en mémoire entre deux recherches."""

    def __init__(self, base_url: str = OFFICIAL_URL, proxy: str | None = None):
        self.base_url, self.proxy = base_url, proxy

    def _http(self) -> httpx.Client:
        return httpx.Client(trust_env=False, follow_redirects=False, proxy=self.proxy, verify=_tls_context(),
                            timeout=httpx.Timeout(READ_TIMEOUT_S, connect=CONNECT_TIMEOUT_S))

    def file_report(self, digest: str, api_key: str) -> Report:
        """`GET /api/v3/files/{empreinte}`. Renvoie le résumé du rapport, ou « inconnu » si VirusTotal ne connaît pas
        ce fichier. Lève VirusTotalError pour tout le reste."""
        kind = hash_kind(digest)
        if kind is None:
            raise ValueError("empreinte invalide")
        deadline = time.monotonic() + TOTAL_TIMEOUT_S
        headers = {"x-apikey": api_key, "Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "keryx"}
        try:
            with self._http() as http, http.stream("GET", f"{self.base_url}/api/v3/files/{digest}", headers=headers) as r:
                status = r.status_code
                if 300 <= status < 400:
                    raise VirusTotalError(502, "VirusTotal a répondu par une redirection : Keryx ne la suit pas.", "redirection")
                if status in (401, 403):
                    raise VirusTotalError(502, "VirusTotal refuse votre clé d'API : vérifiez-la ou remplacez-la dans votre profil.",
                                          "cle_refusee")
                if status == 429:
                    raise VirusTotalError(429, "Le quota de requêtes de votre clé VirusTotal est atteint (par minute ou par "
                                               "jour) : réessayez plus tard.", "quota")
                if status not in (200, 404):
                    raise VirusTotalError(502, f"VirusTotal a répondu par une erreur ({status}).", f"statut_{status}")
                body = _decode(_read_bounded(r, deadline), r.headers.get("content-encoding"))
        except VirusTotalError:
            raise
        except httpx.TimeoutException as exc:
            raise VirusTotalError(503, "VirusTotal n'a pas répondu dans le délai imparti.", "delai") from exc
        except httpx.ProxyError as exc:
            raise VirusTotalError(503, "Le mandataire configuré pour VirusTotal a refusé ou interrompu la liaison.", "mandataire") from exc
        except httpx.ConnectError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc):
                raise VirusTotalError(502, "Le certificat TLS présenté pour VirusTotal n'est pas valide.", "certificat_refuse") from exc
            raise VirusTotalError(503, "VirusTotal est injoignable depuis le serveur Keryx.", "injoignable") from exc
        except httpx.NetworkError as exc:
            raise VirusTotalError(503, "La liaison avec VirusTotal a été interrompue.", "liaison_interrompue") from exc
        except httpx.HTTPError as exc:
            raise VirusTotalError(502, "La réponse de VirusTotal n'est pas une réponse HTTP valide.", "reponse_invalide") from exc
        try:
            doc = json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise VirusTotalError(502, "La réponse de VirusTotal n'est pas celle de son API.", "reponse_invalide") from exc
        if status == 404:
            # « Inconnu » seulement si c'est bien l'API qui le dit (enveloppe d'erreur JSON), pas une page 404 quelconque
            # d'un mandataire ou d'une mauvaise adresse : un faux « inconnu » serait inscrit au registre.
            if not (isinstance(doc, dict) and isinstance(doc.get("error"), dict)):
                raise VirusTotalError(502, "La réponse de VirusTotal n'est pas celle de son API.", "reponse_invalide")
            return Report("inconnu")
        data = doc.get("data") if isinstance(doc, dict) else None
        attributes = data.get("attributes") if isinstance(data, dict) else None
        if not isinstance(attributes, dict):
            raise VirusTotalError(502, "La réponse de VirusTotal n'est pas celle de son API.", "reponse_invalide")
        announced = attributes.get(kind)
        if isinstance(announced, str) and announced.lower() != digest:
            # Le rapport porte une autre empreinte que celle demandée : il n'est pas attribué à ce fichier.
            raise VirusTotalError(502, "VirusTotal a renvoyé le rapport d'un autre fichier que celui demandé.", "reponse_incoherente")
        return Report("trouve", summarize(attributes))


def _read_bounded(r: httpx.Response, deadline: float) -> bytes:
    declared = r.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise VirusTotalError(502, "La réponse de VirusTotal dépasse la taille admise.", "reponse_trop_grande")
    buf = bytearray()
    for chunk in r.iter_raw(65536):
        buf += chunk
        if len(buf) > MAX_RESPONSE_BYTES:
            raise VirusTotalError(502, "La réponse de VirusTotal dépasse la taille admise.", "reponse_trop_grande")
        if time.monotonic() > deadline:
            raise VirusTotalError(503, "VirusTotal n'a pas répondu dans le délai imparti.", "delai")
    return bytes(buf)


def _decode(raw: bytes, encoding: str | None) -> bytes:
    """Keryx demande une réponse non compressée. Si elle arrive tout de même en gzip, elle est décompressée avec la
    même borne de taille (pas de « bombe » de décompression) ; tout autre codage est refusé."""
    encoding = (encoding or "identity").strip().lower()
    if encoding == "identity":
        return raw
    if encoding not in ("gzip", "x-gzip"):
        raise VirusTotalError(502, "La réponse de VirusTotal est dans un codage que Keryx n'accepte pas.", "codage_refuse")
    try:
        unzip = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = unzip.decompress(raw, MAX_RESPONSE_BYTES + 1)
    except zlib.error as exc:
        raise VirusTotalError(502, "La réponse de VirusTotal n'est pas celle de son API.", "reponse_invalide") from exc
    if len(out) > MAX_RESPONSE_BYTES or unzip.unconsumed_tail:
        raise VirusTotalError(502, "La réponse de VirusTotal dépasse la taille admise.", "reponse_trop_grande")
    return out
