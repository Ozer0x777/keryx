"""Contexte Wazuh d'un ticket : lien vers l'alerte dans le tableau de bord et lecture, dans l'indexeur Wazuh, des
événements du même agent qui entourent l'alerte d'origine. Désactivé tant que le client n'est pas configuré. [ADR-0021]

[PDIS IV.2.1.aa contexte rattaché à l'alerte ; PRIS VI.5.3.c registre des informations collectées ; ISO/IEC 27037 et
RFC 3227 (intégrité de la preuve) ; PDIS IV.3.8.g cloisonnement ; RFC 7617 (authentification Basic) ; RFC 3339 (dates)]

Appel sortant borné (voir ADR-0021, « règle de sortie ») :
- HTTPS uniquement, jamais d'identifiants dans l'URL, aucune redirection suivie, aucun mandataire d'environnement ;
- le nom est résolu ici, chaque adresse obtenue est contrôlée, et la connexion part vers l'adresse contrôlée (pas de
  seconde résolution entre le contrôle et la connexion) ;
- adresses refusées : non spécifiée, lien local (dont les services de métadonnées 169.254.169.254), adresses de
  métadonnées connues, multidiffusion, réservées ; la boucle locale est refusée sauf KERYX_WAZUH_ALLOW_LOOPBACK ;
- les adresses privées (RFC 1918, ULA) sont ACCEPTÉES : un indexeur Wazuh vit normalement sur un réseau interne ;
- délai court, taille de réponse bornée, réponse non compressée, JSON seulement.
Ce module n'a été essayé que contre le faux indexeur des tests (tests/fake_indexer.py), jamais contre un vrai Wazuh.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import quote, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from .ids import as_utc, parse_timestamp_strict, rfc3339
from .models import RawAlert, Tenant, Ticket

log = logging.getLogger("keryx.wazuh")

ALLOWED_COUNTS = (5, 10, 15)
DEFAULT_INDEX_PATTERN = "wazuh-alerts-*"
DEFAULT_TIME_FIELD = "@timestamp"
CONNECT_TIMEOUT_S = 3.0
TOTAL_TIMEOUT_S = 8.0            # pour l'ensemble de la récupération (connexion + les deux recherches)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_BYTES = 1024 * 1024
TOKEN_TTL = timedelta(minutes=30)
DOCUMENT_FORMAT = "keryx-wazuh-context-v1"
METHOD_LABEL = "Extraction indexeur Wazuh"

# Champs demandés à l'indexeur (le reste du document n'est pas rapatrié).
SOURCE_FIELDS = ["id", "rule.id", "rule.level", "rule.description", "agent.id", "agent.name", "manager.name", "cluster.name",
                 "location", "decoder.name", "full_log", "data"]


class ConfigError(ValueError):
    """Réglage refusé : le message est destiné à l'Admin (jamais de secret dedans)."""


class IndexerError(Exception):
    """Échec de la lecture de l'indexeur. `message` est montré à l'analyste, `reason` va dans l'audit et les journaux.
    Ni l'un ni l'autre ne contient d'identifiant, d'en-tête ou de corps de réponse."""

    def __init__(self, status: int, message: str, reason: str):
        super().__init__(message)
        self.status, self.message, self.reason = status, message, reason


# ---------------------------------------------------------------- lien vers l'alerte (tableau de bord)
LINK_VARIABLES = {
    "alert_id": "identifiant Wazuh de l'alerte d'origine (champ « id » de l'alerte)",
    "agent_id": "identifiant de l'agent Wazuh du ticket",
    "rule_id": "identifiant de la règle Wazuh du ticket",
    "timestamp": "date de l'alerte d'origine, UTC, RFC 3339",
    "from": "cinq minutes avant l'alerte, UTC, RFC 3339 (borne d'une recherche)",
    "to": "cinq minutes après l'alerte, UTC, RFC 3339 (borne d'une recherche)",
    "index_pattern": "motif d'index du client (wazuh-alerts-* par défaut)",
}
_PLACEHOLDER = re.compile(r"\{([^{}]*)\}")
# Valeurs substituées dans un lien : l'identifiant vient de l'alerte (donnée non fiable). Hors de ce jeu de
# caractères, aucun lien n'est produit plutôt qu'un lien dont le sens pourrait être détourné.
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def _no_blank_or_control(value: str, what: str) -> None:
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ConfigError(f"{what} : espaces, caractères de contrôle et barres obliques inverses interdits.")


def validate_dashboard_template(value: str) -> str:
    """Modèle d'URL du tableau de bord Wazuh : HTTPS, sans identifiants, variables connues seulement et jamais dans
    le nom d'hôte."""
    v = (value or "").strip()
    if not v:
        raise ConfigError("Modèle d'URL vide.")
    if len(v) > 500:
        raise ConfigError("Modèle d'URL trop long (500 caractères maximum).")
    _no_blank_or_control(v, "Modèle d'URL")
    names = _PLACEHOLDER.findall(v)
    unknown = [n for n in names if n not in LINK_VARIABLES]
    accepted = ", ".join("{" + n + "}" for n in LINK_VARIABLES)
    if unknown:
        extra = (" Keryx ne connaît ni l'index réel ni l'identifiant interne (_id) du document : utiliser une "
                 "recherche sur {alert_id}.") if unknown[0] in ("index", "doc_id", "_id") else ""
        raise ConfigError(f"Variable inconnue dans le modèle d'URL : {{{unknown[0][:40]}}}. Variables acceptées : {accepted}.{extra}")
    if "{" in _PLACEHOLDER.sub("", v) or "}" in _PLACEHOLDER.sub("", v):
        raise ConfigError("Accolade isolée dans le modèle d'URL (écrire %7B ou %7D pour une accolade littérale).")
    if not names:
        raise ConfigError(f"Le modèle d'URL doit désigner l'alerte par au moins une variable : {accepted}.")
    try:
        u = urlsplit(v)
        _ = u.port
    except ValueError as exc:
        raise ConfigError("Modèle d'URL invalide.") from exc
    if u.scheme != "https":
        raise ConfigError("Le modèle d'URL doit commencer par https://.")
    if "@" in u.netloc:
        raise ConfigError("Le modèle d'URL ne doit pas contenir d'identifiants (utilisateur:motdepasse@).")
    if not u.hostname or "{" in u.netloc:
        raise ConfigError("Le modèle d'URL doit avoir un nom d'hôte fixe (aucune variable dans l'hôte).")
    return v


def alert_link(template: str | None, *, alert_id: str | None, agent_id: str | None, rule_id: str | None,
               when: datetime | None, index_pattern: str | None) -> str | None:
    """Adresse de l'alerte dans le tableau de bord, ou None si elle ne peut pas être construite sûrement."""
    if not template or not alert_id or not _SAFE_VALUE.match(alert_id):
        return None
    names = set(_PLACEHOLDER.findall(template))
    if names & {"timestamp", "from", "to"} and when is None:
        return None
    values = {
        "alert_id": alert_id,
        "agent_id": agent_id if agent_id and _SAFE_VALUE.match(agent_id) else "",
        "rule_id": rule_id if rule_id and _SAFE_VALUE.match(rule_id) else "",
        "index_pattern": index_pattern or DEFAULT_INDEX_PATTERN,
        "timestamp": rfc3339(when) or "",
        "from": rfc3339(when - timedelta(minutes=5)) if when else "",
        "to": rfc3339(when + timedelta(minutes=5)) if when else "",
    }
    url = _PLACEHOLDER.sub(lambda m: quote(values.get(m.group(1), ""), safe=""), template)
    return url if url.startswith("https://") else None


# ---------------------------------------------------------------- ce que la fiche d'un ticket en sait
def context_configured(tenant: Tenant) -> bool:
    """La lecture de l'indexeur n'existe pour un client que si l'adresse ET le compte de lecture sont réglés."""
    return bool(tenant.wazuh_indexer_url and tenant.wazuh_indexer_user and tenant.wazuh_indexer_password)


def origin_alert(db: DbSession, t: Ticket) -> tuple[str | None, datetime | None, dict | None]:
    """Alerte d'origine du ticket : la plus ancienne alerte brute conservée qui porte l'agent du ticket (une fusion
    peut y avoir rattaché les alertes d'un autre ticket). Renvoie (identifiant Wazuh, date UTC, alerte) ou des None
    si elle n'est plus conservée (rétention)."""
    rows = db.scalars(select(RawAlert).where(RawAlert.ticket_id == t.id)
                      .order_by(RawAlert.received_at, RawAlert.id).limit(25)).all()
    for r in rows:
        try:
            payload = json.loads(r.payload)
        except ValueError:
            continue
        agent = payload.get("agent") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or "rule" not in payload:
            continue
        agent_id = agent.get("id") if isinstance(agent, dict) else None
        agent_id = "" if agent_id is None or isinstance(agent_id, (dict, list)) else str(agent_id)[:32]
        if agent_id == (t.agent_id or ""):
            raw_ts = payload.get("timestamp")
            return r.wazuh_id, parse_timestamp_strict(raw_ts if isinstance(raw_ts, str) else None), payload
    return None, None, None


def ticket_view(db: DbSession, t: Ticket, tenant: Tenant) -> dict | None:
    """Bloc « wazuh » de la fiche, pour l'équipe seulement (jamais le client, jamais l'Admin) : adresse de l'alerte
    dans le tableau de bord et disponibilité de la lecture de l'indexeur. None : rien n'est réglé, rien n'est montré."""
    link = None
    if tenant.wazuh_dashboard_url:
        alert_id, when, _ = origin_alert(db, t)
        link = alert_link(tenant.wazuh_dashboard_url, alert_id=alert_id, agent_id=t.agent_id, rule_id=t.rule_id,
                          when=when or as_utc(t.detected_at), index_pattern=tenant.wazuh_index_pattern)
    context = context_configured(tenant) and bool(t.agent_id)
    if not link and not context:
        return None
    return {"alert_url": link, "context": context}


# ---------------------------------------------------------------- adresse de l'indexeur et règle de sortie
@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int
    base_path: str = ""

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"https://{host}{'' if self.port == 443 else f':{self.port}'}{self.base_path}"

    @property
    def label(self) -> str:
        """Hôte et port, pour l'audit et la provenance d'une preuve (jamais d'identifiant)."""
        return f"{self.host}:{self.port}"


_HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")
_BASE_PATH = re.compile(r"^(/[A-Za-z0-9._~-]+)*$")
_INDEX_PATTERN = re.compile(r"^[a-z0-9*][a-z0-9*._-]{0,127}$")
_TIME_FIELD = re.compile(r"^[A-Za-z@_][A-Za-z0-9_.@-]{0,63}$")
# Noms connus des services de métadonnées : refus dès la saisie. Le contrôle qui fait foi reste celui des adresses
# résolues au moment de l'appel (ces noms pointent tous vers une adresse de lien local).
_METADATA_NAMES = {"metadata", "metadata.google.internal", "metadata.goog", "instance-data", "instance-data.ec2.internal"}
_METADATA_ADDRESSES = {ipaddress.ip_address(a) for a in ("169.254.169.254", "100.100.100.200", "192.0.0.192", "fd00:ec2::254")}
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def address_refusal(address: str, allow_loopback: bool = False) -> str | None:
    """Motif de refus d'une adresse IP de destination, ou None si elle est acceptée (règle de sortie, ADR-0021)."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "adresse illisible"
    candidates = [ip]
    if ip.version == 6:
        if ip.ipv4_mapped is not None:          # ::ffff:a.b.c.d : c'est l'adresse IPv4 qui est jugée
            candidates = [ip.ipv4_mapped]
        elif ip.sixtofour is not None:          # 2002::/16 : l'adresse IPv4 embarquée est jugée aussi
            candidates.append(ip.sixtofour)
        elif ip in _NAT64:
            candidates = [ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)]
    for a in candidates:
        if a.is_loopback:
            if not allow_loopback:
                return "boucle locale"
            continue
        if a.is_unspecified or (a.version == 4 and a in ipaddress.ip_network("0.0.0.0/8")):
            return "adresse non spécifiée"
        if a.is_link_local:
            return "adresse de lien local (dont les services de métadonnées)"
        if a in _METADATA_ADDRESSES:
            return "adresse d'un service de métadonnées"
        if a.is_multicast:
            return "adresse de multidiffusion"
        if a.is_reserved:
            return "adresse réservée"
    return None


def parse_indexer_url(value: str, allow_loopback: bool = False) -> Endpoint:
    """Adresse de l'indexeur : https://hôte[:port][/préfixe]. Pas d'identifiants, de requête ni de fragment."""
    v = (value or "").strip()
    if not v:
        raise ConfigError("Adresse de l'indexeur vide.")
    if len(v) > 300:
        raise ConfigError("Adresse de l'indexeur trop longue (300 caractères maximum).")
    _no_blank_or_control(v, "Adresse de l'indexeur")
    try:
        u = urlsplit(v)
        port = u.port
    except ValueError as exc:
        raise ConfigError("Adresse de l'indexeur invalide.") from exc
    if u.scheme != "https":
        raise ConfigError("L'adresse de l'indexeur doit commencer par https://.")
    if "@" in u.netloc:
        raise ConfigError("L'adresse de l'indexeur ne doit pas contenir d'identifiants : les saisir dans les champs prévus.")
    if u.query or u.fragment or "?" in v or "#" in v:
        raise ConfigError("L'adresse de l'indexeur ne doit comporter ni paramètres ni fragment.")
    host = (u.hostname or "").rstrip(".").lower()
    if not host:
        raise ConfigError("L'adresse de l'indexeur doit comporter un nom d'hôte.")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError("Port de l'indexeur invalide.")
    try:
        ipaddress.ip_address(host)
        literal = True
    except ValueError:
        literal = False
    if literal:
        reason = address_refusal(host, allow_loopback)
        if reason:
            raise ConfigError(f"Adresse de l'indexeur refusée : {reason}.")
    else:
        if not _HOSTNAME.match(host):
            raise ConfigError("Nom d'hôte de l'indexeur invalide (lettres, chiffres, tirets et points).")
        if host in _METADATA_NAMES:
            raise ConfigError("Adresse de l'indexeur refusée : service de métadonnées.")
        if (host == "localhost" or host.endswith(".localhost")) and not allow_loopback:
            raise ConfigError("Adresse de l'indexeur refusée : boucle locale.")
    path = u.path.rstrip("/")
    if not _BASE_PATH.match(path) or ".." in path.split("/"):
        raise ConfigError("Préfixe de chemin de l'indexeur invalide.")
    return Endpoint(host, port or 443, path)


_SOURCE = re.compile(r"^(manager|cluster):([A-Za-z0-9][A-Za-z0-9._-]{0,127})$")
SOURCE_KINDS = ("manager", "cluster")


def validate_source(value: str) -> str:
    """Source Wazuh d'un client : « manager:<nom> » (champ manager.name) ou « cluster:<nom> » (champ cluster.name)."""
    v = (value or "").strip()
    m = _SOURCE.match(v)
    if not m:
        raise ConfigError("Source Wazuh invalide : « manager:<nom du manager> » ou « cluster:<nom du cluster> » "
                          "(lettres, chiffres, « . », « - », « _ »).")
    return f"{m.group(1)}:{m.group(2)}"


def parse_source(value: str | None) -> tuple[str, str] | None:
    """(type, nom) d'une source réglée, ou None si elle est absente ou n'a pas la forme attendue."""
    m = _SOURCE.match((value or "").strip())
    return (m.group(1), m.group(2)) if m else None


def source_filter(cfg: IndexerConfig) -> list[dict]:
    """Filtre de l'indexeur sur la source du client : le champ de son type seulement (manager.name, ou cluster.name dans
    un cluster, où manager.name est le nœud qui a traité l'alerte). Vide si aucune source n'est réglée."""
    parsed = parse_source(cfg.source)
    return [{"term": {f"{parsed[0]}.name": parsed[1]}}] if parsed else []


def from_source(src: dict, source: str | None) -> bool:
    """Vrai si l'événement vient de la source du client (toujours vrai sans source réglée)."""
    parsed = parse_source(source)
    if not parsed:
        return not source
    field = src.get(parsed[0])
    return isinstance(field, dict) and field.get("name") == parsed[1]


def _prefix(pattern: str) -> str:
    return pattern.split("*", 1)[0]


def patterns_overlap(a: str, b: str) -> bool:
    """Prudent : deux motifs d'index peuvent couvrir les mêmes index si l'un est égal à l'autre, ou si les parties fixes
    avant la première étoile se prolongent l'une l'autre (wazuh-alerts-* et wazuh-alerts-4.x-*)."""
    if a == b:
        return True
    if "*" not in a and "*" not in b:
        return False
    pa, pb = _prefix(a), _prefix(b)
    if "*" not in a:
        return a.startswith(pb)
    if "*" not in b:
        return b.startswith(pa)
    return pa.startswith(pb) or pb.startswith(pa)


def source_conflict(db: DbSession, tenant: Tenant, strict: bool = True) -> Tenant | None:
    """Autre client dont les événements pourraient être lus avec la source de celui-ci [PDIS IV.3.8.g ; ADR-0031].

    Les adresses des indexeurs ne sont PAS comparées : un même serveur s'écrit de bien des façons (adresse IP sous
    plusieurs formes, alias DNS, IPv6). Deux clients dont les motifs d'index peuvent se recouvrir doivent donc, quel que
    soit leur indexeur, avoir chacun une source, du même type (deux noms de types différents ne s'excluent pas : un
    manager et un cluster peuvent porter le même nom) et de noms différents. `strict=False` (enregistrement d'un client) :
    un autre client encore sans source n'empêche pas d'enregistrer la sienne, pour qu'un Admin puisse régler les
    clients un par un ; la lecture (`strict=True`) reste refusée tant que tous ne sont pas réglés."""
    if not tenant.wazuh_indexer_url:
        return None
    pattern = tenant.wazuh_index_pattern or DEFAULT_INDEX_PATTERN
    mine = parse_source(tenant.wazuh_indexer_source)
    for other in db.scalars(select(Tenant).where(Tenant.id != tenant.id, Tenant.wazuh_indexer_url.is_not(None))
                            .order_by(Tenant.key)):
        if not patterns_overlap(pattern, other.wazuh_index_pattern or DEFAULT_INDEX_PATTERN):
            continue
        theirs = parse_source(other.wazuh_indexer_source)
        if mine is None:
            return other
        if theirs is None:
            if strict:
                return other
            continue
        if theirs[0] != mine[0] or theirs[1].lower() == mine[1].lower():
            return other
    return None


def validate_index_pattern(value: str) -> str:
    v = (value or "").strip()
    if not _INDEX_PATTERN.match(v):
        raise ConfigError("Motif d'index invalide : minuscules, chiffres, « . », « - », « _ » et « * » (ex. wazuh-alerts-*), "
                          "sans virgule ni « : ».")
    return v


def validate_time_field(value: str) -> str:
    if not _TIME_FIELD.match(value or ""):
        raise ValueError("KERYX_WAZUH_TIME_FIELD invalide (ex. timestamp ou @timestamp).")
    return value


def normalize_ca_pem(value: str) -> str:
    """Certificats d'autorité au format PEM, relus puis réécrits : seul ce qui est un certificat est conservé."""
    if "PRIVATE KEY" in value:
        raise ConfigError("Ne collez jamais de clé privée : seul le certificat de l'autorité (PEM) est attendu.")
    try:
        certs = x509.load_pem_x509_certificates(value.encode("ascii", "strict"))
    except (ValueError, UnicodeError) as exc:
        raise ConfigError("Certificat d'autorité illisible : format PEM attendu (-----BEGIN CERTIFICATE-----).") from exc
    if not certs or len(certs) > 10:
        raise ConfigError("Entre 1 et 10 certificats d'autorité attendus.")
    return "".join(c.public_bytes(Encoding.PEM).decode("ascii") for c in certs)


def validate_username(value: str) -> str:
    if not value or len(value) > 128 or ":" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError("Identifiant de l'indexeur invalide (128 caractères maximum, sans « : » ni caractère de contrôle).")
    return value


def validate_password(value: str) -> str:
    if not value or len(value) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError("Mot de passe de l'indexeur invalide (256 caractères maximum, sans caractère de contrôle).")
    return value


# ---------------------------------------------------------------- appel de l'indexeur
@dataclass
class IndexerConfig:
    endpoint: Endpoint
    username: str = field(repr=False)
    password: str = field(repr=False)
    tls_verify: bool = True
    ca_pem: str | None = field(default=None, repr=False)
    index_pattern: str = DEFAULT_INDEX_PATTERN
    time_field: str = DEFAULT_TIME_FIELD
    allow_loopback: bool = False
    source: str | None = None      # manager.name ou cluster.name des événements du client (ADR-0031)


def _tls_context(cfg: IndexerConfig) -> ssl.SSLContext:
    try:
        if not cfg.tls_verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif cfg.ca_pem:
            # Autorité du client : elle remplace le magasin du système (seule cette autorité est acceptée).
            ctx = ssl.create_default_context(cadata=cfg.ca_pem)
            # Les autorités privées (outil de certificats de Wazuh) ne suivent pas toujours la RFC 5280 à la lettre :
            # le contrôle strict ajouté par défaut depuis Python 3.13 est retiré, la chaîne et le nom restent vérifiés.
            ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
        else:
            ctx = ssl.create_default_context()
    except ssl.SSLError as exc:
        raise IndexerError(502, "Le certificat d'autorité configuré pour l'indexeur Wazuh est illisible.", "ca_illisible") from exc
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def resolve(endpoint: Endpoint, allow_loopback: bool) -> list[str]:
    """Résout le nom et applique la règle de sortie à CHAQUE adresse : une seule adresse refusée refuse l'appel."""
    try:
        infos = socket.getaddrinfo(endpoint.host, endpoint.port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise IndexerError(503, "L'indexeur Wazuh est injoignable (nom d'hôte introuvable).", "nom_introuvable") from exc
    addresses = list(dict.fromkeys(i[4][0] for i in infos))
    if not addresses:
        raise IndexerError(503, "L'indexeur Wazuh est injoignable (nom d'hôte introuvable).", "nom_introuvable")
    for a in addresses:
        reason = address_refusal(a, allow_loopback)
        if reason:
            raise IndexerError(502, f"L'adresse de l'indexeur Wazuh est refusée par la règle de sortie de Keryx : {reason}.",
                               "adresse_refusee")
    return addresses


def _connect(cfg: IndexerConfig, deadline: float) -> ssl.SSLSocket:
    """Ouvre la connexion TLS vers une adresse contrôlée. Le connecteur reste entre les mains de Keryx : aucune
    bibliothèque HTTP ne résout de nom, ne se reconnecte ni ne suit de redirection à sa place."""
    ctx = _tls_context(cfg)
    last: Exception | None = None
    for address in resolve(cfg.endpoint, cfg.allow_loopback):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock = None
        try:
            sock = socket.create_connection((address.split("%", 1)[0], cfg.endpoint.port), timeout=min(CONNECT_TIMEOUT_S, remaining))
            return ctx.wrap_socket(sock, server_hostname=cfg.endpoint.host)
        except ssl.SSLCertVerificationError as exc:
            sock.close()
            raise IndexerError(502, "Le certificat TLS de l'indexeur Wazuh n'est pas valide pour Keryx "
                                    "(autorité inconnue, nom différent ou certificat expiré).", "certificat_refuse") from exc
        except ssl.SSLError as exc:
            sock.close()
            raise IndexerError(502, "La négociation TLS avec l'indexeur Wazuh a échoué.", "tls") from exc
        except OSError as exc:      # refus de connexion, délai dépassé, réseau injoignable : adresse suivante
            if sock is not None:
                sock.close()
            last = exc
    if isinstance(last, TimeoutError):
        raise IndexerError(503, "L'indexeur Wazuh n'a pas répondu dans le délai imparti.", "delai") from last
    raise IndexerError(503, "L'indexeur Wazuh est injoignable.", "injoignable") from last


def _read_bounded(sock: socket.socket, resp: http.client.HTTPResponse, deadline: float) -> bytes:
    declared = resp.getheader("Content-Length")
    if declared and declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise IndexerError(502, "La réponse de l'indexeur Wazuh dépasse la taille admise.", "reponse_trop_grande")
    buf = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(remaining)
        chunk = resp.read1(65536)
        if not chunk:
            return bytes(buf)
        buf += chunk
        if len(buf) > MAX_RESPONSE_BYTES:
            raise IndexerError(502, "La réponse de l'indexeur Wazuh dépasse la taille admise.", "reponse_trop_grande")


def search_body(cfg: IndexerConfig, agent_id: str, pivot: str, direction: str, size: int) -> dict:
    """Recherche des événements d'UN agent, d'un côté de l'instant pivot. `before` : les plus récents avant ;
    `after` : les plus anciens à partir du pivot (l'alerte elle-même en fait partie et sera écartée)."""
    before = direction == "before"
    return {
        "size": size,
        "track_total_hits": False,
        "_source": [*SOURCE_FIELDS, cfg.time_field],
        "query": {"bool": {"filter": [
            {"term": {"agent.id": agent_id}},
            {"range": {cfg.time_field: {"lt" if before else "gte": pivot, "format": "strict_date_optional_time"}}},
            *source_filter(cfg),
        ]}},
        "sort": [{cfg.time_field: {"order": "desc" if before else "asc", "unmapped_type": "date"}}],
    }


def _search(sock: ssl.SSLSocket, cfg: IndexerConfig, body: dict, deadline: float) -> tuple[list[dict], bool]:
    """Une recherche `_search` sur la connexion ouverte. Renvoie (résultats, connexion réutilisable)."""
    path = (f"{cfg.endpoint.base_path}/{quote(cfg.index_pattern, safe='*._-')}/_search"
            "?ignore_unavailable=true&allow_no_indices=true")
    host = f"[{cfg.endpoint.host}]" if ":" in cfg.endpoint.host else cfg.endpoint.host
    if cfg.endpoint.port != 443:
        host += f":{cfg.endpoint.port}"
    credentials = base64.b64encode(f"{cfg.username}:{cfg.password}".encode("utf-8")).decode("ascii")
    payload = json.dumps(body).encode("utf-8")
    # Requête écrite ici (chaque valeur est validée ou encodée) et réponse lue par l'analyseur de http.client, sans son
    # connecteur : pas de reconnexion automatique, pas de redirection, pas de mandataire d'environnement.
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {credentials}\r\n"
            "Content-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\n"
            f"User-Agent: keryx\r\nContent-Length: {len(payload)}\r\n\r\n").encode("ascii")
    sock.settimeout(max(0.1, deadline - time.monotonic()))
    sock.sendall(head + payload)
    resp = http.client.HTTPResponse(sock, method="POST")
    try:
        resp.begin()
        if 300 <= resp.status < 400:
            raise IndexerError(502, "L'indexeur Wazuh a répondu par une redirection : Keryx ne la suit pas "
                                    "(vérifier l'adresse configurée).", "redirection")
        if resp.status in (401, 403):
            raise IndexerError(502, "L'indexeur Wazuh refuse le compte de lecture configuré (identifiants ou droits).",
                               "authentification")
        data = _read_bounded(sock, resp, deadline)
        status, reusable = resp.status, not resp.will_close
    finally:
        resp.close()
    if status != 200:
        raise IndexerError(502, f"L'indexeur Wazuh a répondu par une erreur ({status}).", f"statut_{status}")
    try:
        doc = json.loads(data)
        hits = doc["hits"]["hits"]
        if not isinstance(hits, list):
            raise TypeError
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        raise IndexerError(502, "La réponse de l'indexeur Wazuh n'est pas celle d'une recherche OpenSearch.", "reponse_invalide") from exc
    return [h for h in hits[: body["size"]] if isinstance(h, dict)], reusable


@dataclass
class Context:
    before: list[dict]
    after: list[dict]
    dropped: int      # événements écartés par Keryx (autre agent, hors de la fenêtre) : l'indexeur n'est pas cru sur parole


def fetch(cfg: IndexerConfig, agent_id: str, pivot: datetime, alert_id: str | None, before: int, after: int) -> Context:
    """Lit `before` événements avant et `after` événements après l'instant de l'alerte, pour le seul agent du ticket."""
    if before not in ALLOWED_COUNTS or after not in ALLOWED_COUNTS:
        raise ValueError("fenêtre non autorisée")
    if not agent_id:
        raise ValueError("agent absent")
    deadline = time.monotonic() + TOTAL_TIMEOUT_S
    at = rfc3339(pivot)
    pivot = parse_timestamp_strict(at)      # même précision (milliseconde) pour la requête et pour le contrôle local
    sock = None
    try:
        sock = _connect(cfg, deadline)
        raw_before, reusable = _search(sock, cfg, search_body(cfg, agent_id, at, "before", before), deadline)
        if not reusable:           # « Connection: close » : nouvelle connexion, de nouveau contrôlée
            sock.close()
            sock = None
            sock = _connect(cfg, deadline)
        raw_after, _ = _search(sock, cfg, search_body(cfg, agent_id, at, "after", after + 1), deadline)
    except IndexerError:
        raise
    except TimeoutError as exc:
        raise IndexerError(503, "L'indexeur Wazuh n'a pas répondu dans le délai imparti.", "delai") from exc
    except ssl.SSLError as exc:
        raise IndexerError(502, "La liaison TLS avec l'indexeur Wazuh a été interrompue.", "tls") from exc
    except ConnectionError as exc:
        raise IndexerError(503, "La liaison avec l'indexeur Wazuh a été interrompue.", "liaison_interrompue") from exc
    except http.client.HTTPException as exc:
        raise IndexerError(502, "La réponse de l'indexeur Wazuh n'est pas une réponse HTTP valide.", "reponse_invalide") from exc
    except OSError as exc:
        raise IndexerError(503, "La liaison avec l'indexeur Wazuh a été interrompue.", "liaison_interrompue") from exc
    finally:
        if sock is not None:
            sock.close()

    dropped = 0

    def keep(hits: list[dict], side: str) -> list[dict]:
        nonlocal dropped
        out = []
        for h in hits:
            src = h.get("_source")
            agent = src.get("agent") if isinstance(src, dict) else None
            if not isinstance(agent, dict) or str(agent.get("id")) != agent_id or not from_source(src, cfg.source):
                dropped += 1          # jamais l'événement d'un autre agent ou d'un autre manager, même renvoyé par l'indexeur
                continue
            entry = entry_from_source(src, cfg.time_field)
            if alert_id and entry["id"] == alert_id:
                continue              # l'alerte d'origine est affichée à part, depuis la copie conservée par Keryx
            when = parse_timestamp_strict(entry["timestamp"])
            if when is not None and ((side == "before" and when >= pivot) or (side == "after" and when < pivot)):
                dropped += 1
                continue
            out.append(entry)
        return out

    def order(e: dict) -> tuple:
        return (e["timestamp"] or "", e["id"])

    kept_before = sorted(keep(raw_before, "before"), key=order)[-before:]
    kept_after = sorted(keep(raw_after, "after"), key=order)[:after]
    return Context(kept_before, kept_after, dropped)


# ---------------------------------------------------------------- assainissement (texte pur, borné)
_BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f")


def clean_text(value, limit: int, multiline: bool = False) -> str:
    """Texte pur et borné : jamais de structure, pas de caractère de contrôle (sauf retour ligne et tabulation d'un
    journal), pas de marque de sens d'écriture (elles permettraient de maquiller une ligne), pas de demi-codet isolé."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    if isinstance(value, bool):
        value = "true" if value else "false"
    text = str(value)[: limit * 2]
    out = []
    for c in text:
        o = ord(c)
        if multiline and c in "\n\t":
            out.append(c)
        elif o < 32 or o == 127 or 0x80 <= o <= 0x9F:
            out.append(f"\\x{o:02x}")
        elif c in _BIDI or 0xD800 <= o <= 0xDFFF:
            out.append("�")
        else:
            out.append(c)
    return "".join(out)[:limit]


def _flatten(value, prefix: str, out: dict, depth: int = 0) -> None:
    if len(out) >= 40 or depth > 6:
        return
    if isinstance(value, dict):
        for k in sorted(value, key=str):
            key = re.sub(r"[^A-Za-z0-9_.@-]", "_", str(k))[:60]
            _flatten(value[k], f"{prefix}.{key}" if prefix else key, out, depth + 1)
    elif isinstance(value, list):
        scalars = [clean_text(x, 200) for x in value[:20] if not isinstance(x, (dict, list))]
        if scalars and prefix and len(out) < 40:
            out[prefix[:120]] = ", ".join(scalars)[:500]
    elif value is not None and prefix and len(out) < 40:
        out[prefix[:120]] = clean_text(value, 500)


def entry_from_source(src: dict, time_field: str = DEFAULT_TIME_FIELD) -> dict:
    """Événement Wazuh ramené à des champs de texte bornés (jamais de HTML, jamais de structure libre)."""
    def d(v):
        return v if isinstance(v, dict) else {}
    rule, agent, decoder = d(src.get("rule")), d(src.get("agent")), d(src.get("decoder"))
    raw_ts = src.get(time_field)
    when = parse_timestamp_strict(raw_ts if isinstance(raw_ts, str) else None)
    data: dict[str, str] = {}
    _flatten(src.get("data"), "", data)
    return {
        "timestamp": rfc3339(when),                       # UTC, ou None si la date de l'événement est illisible
        "timestamp_brut": clean_text(raw_ts, 40),
        "id": clean_text(src.get("id"), 64),
        "rule_id": clean_text(rule.get("id"), 32),
        "rule_level": clean_text(rule.get("level"), 4),
        "rule_description": clean_text(rule.get("description"), 500),
        "agent_id": clean_text(agent.get("id"), 32),
        "agent_name": clean_text(agent.get("name"), 200),
        "location": clean_text(src.get("location"), 300),
        "decoder": clean_text(decoder.get("name"), 100),
        "full_log": clean_text(src.get("full_log"), 8000, multiline=True),
        "data": data,
    }


# ---------------------------------------------------------------- jeu récupéré : document, empreinte, sceau
def build_document(*, ticket_ref: str, client_key: str, fetched_at: datetime, fetched_by: str, cfg: IndexerConfig,
                   agent_id: str, alert_id: str | None, alert_at: datetime, alert_source: str, alert_entry: dict,
                   before: int, after: int, context: Context) -> dict:
    return {
        "format": DOCUMENT_FORMAT,
        "ticket": ticket_ref, "client": client_key,
        "fetched_at": rfc3339(fetched_at), "fetched_by": fetched_by,
        "source": {"indexer": cfg.endpoint.label, "index_pattern": cfg.index_pattern, "time_field": cfg.time_field,
                   "agent_id": agent_id, "tls_verified": cfg.tls_verify},
        "alert": {"id": alert_id or "", "timestamp": rfc3339(alert_at), "origin": alert_source},
        "requested": {"before": before, "after": after},
        "before": context.before, "alert_entry": alert_entry, "after": context.after,
    }


def document_bytes(doc: dict) -> bytes:
    """Forme canonique du jeu (clés triées) : c'est elle qui est empreinte, scellée, puis conservée comme preuve."""
    return (json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode("utf-8")


def seal_key(secret_key_b64: str) -> bytes:
    """Clé de scellement des jeux récupérés, dérivée de la clé maîtresse (séparation des usages, comme l'audit)."""
    return hmac.new(base64.b64decode(secret_key_b64), b"keryx-wazuh-context-v1", hashlib.sha256).digest()


def seal(key: bytes, tenant_id: str, ticket_ref: str, username: str, digest: str) -> str:
    """Sceau d'un jeu récupéré : lie le contenu (son empreinte) au client, au ticket et à l'analyste qui l'a obtenu.
    Il permet de conserver plus tard EXACTEMENT ce que Keryx a lu, sans rien écrire en base entre-temps."""
    message = f"{DOCUMENT_FORMAT}:{tenant_id}:{ticket_ref}:{username}:{digest}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()
