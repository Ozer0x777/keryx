"""Modèle de données Keryx.

Chaque table indique entre crochets les exigences qu'elle sert.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    LargeBinary,
    BigInteger,
    false,
    true,
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base
from .ids import utcnow, uuid7

ROLES = ("admin", "manager", "analyst", "client")

# Statuts calqués sur les phases ISO/IEC 27035-1 (détection → évaluation → réponse → enseignements).
STATUSES = (
    "nouveau",            # détection et signalement
    "en_evaluation",      # évaluation et décision (triage, qualification)
    "faux_positif",       # clos après évaluation
    "en_reponse",         # confinement, éradication, rétablissement
    "cloture",            # incident traité
    "retour_experience",  # tirer les enseignements (obligatoire si Élevée/Critique)
)
TERMINAL_STATUSES = ("faux_positif", "cloture", "retour_experience")

SEVERITIES = ("Faible", "Moyenne", "Élevée", "Critique")
VERDICTS = ("vrai_positif_avere", "vrai_positif_non_avere", "faux_positif")
TLP = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")  # FIRST TLP 2.0, du moins au plus restrictif
TLP_DEFAUT = "TLP:AMBER"
# Niveau de classification d'un incident au sens d'[IGI_1300] et d'[II_901] (PDIS IV.2.1.e, IV.2.1.w), du moins au plus
# protégé. Keryx ne traite pas d'information classifiée de défense : seuls ces deux niveaux sont proposés.
NIVEAUX_CLASSIFICATION = ("Non protégé", "Diffusion Restreinte")


def tlp_rang(valeur: str | None) -> int:
    """Rang d'un marquage TLP (plus grand = plus restrictif) ; -1 si inconnu ou absent."""
    return TLP.index(valeur) if valeur in TLP else -1


def tlp_initial(plancher: str | None) -> str:
    """Marquage d'un nouveau ticket ou d'une nouvelle pièce d'un client : son plancher, sinon TLP:AMBER (ADR-0033)."""
    return plancher if plancher in TLP else TLP_DEFAUT


def _id() -> Mapped[str]:
    return mapped_column(String(36), primary_key=True, default=uuid7)


class Tenant(Base):
    """Client / commanditaire. [PDIS IV.3.8.g cloisonnement, IV.2.1.bb registre par client]"""
    __tablename__ = "tenants"
    id: Mapped[str] = _id()
    key: Mapped[str] = mapped_column(String(16), unique=True)       # préfixe des références (ACME-123)
    name: Mapped[str] = mapped_column(String(200))
    next_seq: Mapped[int] = mapped_column(Integer, default=1)
    # Grille de gravité propre au client [PDIS IV.2.1.e, r, s]. None = grille par défaut.
    severity_grid: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Destinataires des notifications du client [PDIS IV.2.3.d stratégie de notification]
    contact_emails: Mapped[list] = mapped_column(JSON, default=list)
    # Rétention des alertes brutes en mois (None = valeur par défaut de la configuration) [PDIS IV.2.2.w]
    retention_months: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # PDIS IV.5.3.6 : les incidents, leur contexte (alertes brutes) et les notifications se gardent toute la durée de
    # la prestation. Vrai par défaut : la purge des alertes brutes ne touche pas ce client. L'Admin peut le décocher
    # (prestation hors référentiel, minimisation) ; la durée de rétention s'applique alors.
    conserver_contexte: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    # Contenu du ticket (PDIS IV.2.1.w), réglé par le manager : niveau de classification par défaut des incidents du
    # client, et version du jeu de règles de détection en service (reportée sur chaque ticket créé).
    niveau_classification_defaut: Mapped[str | None] = mapped_column(String(40), nullable=True)
    version_regles: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # Stratégie de notification (PDIS IV.2.3.b, d) : criticité minimale par contact (adresse -> criticité ; absent :
    # toutes) réglée par l'Admin avec les contacts ; moyen secondaire (un canal déclaré par l'Admin, choisi par le
    # manager), utilisé quand le courriel échoue, et date de son dernier essai réussi (au moins tous les six mois).
    contacts_criticite: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    notif_secours_canal_id: Mapped[str | None] = mapped_column(ForeignKey("canaux_astreinte.id"), nullable=True)
    notif_secours_teste_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # PDIS IV.1.g : accord du client avant toute communication d'informations à un tiers. Une recherche VirusTotal
    # envoie une empreinte à un service externe : refusée tant que le manager n'a pas enregistré cet accord.
    virustotal_autorise: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Criticité initiale imposée par règle Wazuh, réglée par le manager pour ce client (identifiant de règle ->
    # criticité) : le niveau Wazuh d'une règle peut ne pas refléter son enjeu chez ce client. Aucune règle en dur.
    criticite_regles: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Délais cibles par gravité, en heures : {"Critique": {"qualification": 1, "resolution": 8}, ...}
    sla: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Taille maximale d'une pièce, en Mio (1 à 20) ; vide = 20 Mio, plafond fixé par le plan [PRIS VI.2.4]
    max_attachment_mb: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Contexte Wazuh [PDIS IV.2.1.aa ; ADR-0021]. Tout est vide par défaut : la fonction est alors masquée.
    # Modèle d'URL de l'alerte dans le tableau de bord Wazuh (variables entre accolades), montré à l'équipe seulement.
    wazuh_dashboard_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Indexeur Wazuh (API OpenSearch) lu pour le contexte d'une alerte : adresse HTTPS, motif d'index (vide = wazuh-alerts-*).
    wazuh_indexer_url: Mapped[str | None] = mapped_column(String(300), nullable=True)
    wazuh_index_pattern: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Source des événements du client dans l'indexeur : nom de son manager Wazuh (manager.name) ou de son cluster
    # (cluster.name). Obligatoire et propre à chaque client quand plusieurs clients lisent le même indexeur avec des
    # motifs d'index qui se recouvrent : les numéros d'agent ne sont uniques que par manager (ADR-0031).
    wazuh_indexer_source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Politique du client (ADR-0033), réglée par le manager : TLP plancher. Les tickets et les pièces du client naissent
    # à ce niveau ; un analyste ne peut pas descendre en dessous, un manager le peut sur un ticket avec un motif.
    # Vide : pas de plancher, les tickets naissent en TLP:AMBER comme avant.
    tlp_plancher: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Délai d'acquittement dans le rapport périodique remis au client (ADR-0032), choix du manager ; toujours visible
    # de l'équipe.
    acquittement_rapport: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    # Astreinte du client (ADR-0032), réglée par le manager : activation, criticités qui la préviennent, délai avant
    # escalade par criticité (minutes), canaux choisis parmi ceux que l'Admin a déclarés. Désactivée par défaut.
    astreinte_active: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    astreinte_criticites: Mapped[list | None] = mapped_column(JSON, nullable=True)
    astreinte_delais: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    astreinte_canal_id: Mapped[str | None] = mapped_column(ForeignKey("canaux_astreinte.id"), nullable=True)
    escalade_canal_id: Mapped[str | None] = mapped_column(ForeignKey("canaux_astreinte.id"), nullable=True)
    # Battement de cœur de la chaîne Wazuh vers Keryx (ADR-0032, partie 3), réglé par le manager : période de la tâche
    # planifiée sur le manager Wazuh, délai d'alerte sans battement ; dernière réception, source, début de l'absence.
    battement_active: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    battement_periode_min: Mapped[int] = mapped_column(Integer, default=5, server_default="5")
    battement_delai_min: Mapped[int] = mapped_column(Integer, default=15, server_default="15")
    battement_depuis: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    battement_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    battement_source: Mapped[str | None] = mapped_column(String(200), nullable=True)
    battement_manquant_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Compte en lecture seule de l'indexeur : chiffré AES-256-GCM comme le secret TOTP (ADR-0006), jamais renvoyé par l'API.
    wazuh_indexer_user: Mapped[str | None] = mapped_column(Text, nullable=True)
    wazuh_indexer_password: Mapped[str | None] = mapped_column(Text, nullable=True)
    wazuh_tls_verify: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    wazuh_ca_pem: Mapped[str | None] = mapped_column(Text, nullable=True)   # autorité de certification propre au client (PEM)
    # Parc d'agents (ADR-0030) : API du manager Wazuh lue en lecture seule. Même autorité et même contrôle TLS que
    # l'indexeur. `wazuh_api_group` : groupe Wazuh des agents du client quand un manager sert plusieurs clients.
    wazuh_api_url: Mapped[str | None] = mapped_column(String(300), nullable=True)
    wazuh_api_user: Mapped[str | None] = mapped_column(Text, nullable=True)       # chiffré, jamais renvoyé par l'API
    wazuh_api_password: Mapped[str | None] = mapped_column(Text, nullable=True)   # chiffré, jamais renvoyé par l'API
    wazuh_api_group: Mapped[str | None] = mapped_column(String(128), nullable=True)
    wazuh_manager_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    wazuh_agents_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    wazuh_agents_error: Mapped[str | None] = mapped_column(String(300), nullable=True)   # dernier échec du relevé, vide si réussi
    # Le dernier relevé a pu lire le dernier événement de chaque agent dans l'indexeur (sinon « silencieux » n'a pas de sens).
    wazuh_events_ok: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class User(Base):
    """Utilisateur. [PDIS IV.3.9 comptes, ISO 27002 5.15/5.17/5.18/8.5, RFC 6238, RFC 9106]"""
    __tablename__ = "users"
    id: Mapped[str] = _id()
    username: Mapped[str] = mapped_column(String(120), unique=True)
    display_name: Mapped[str] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(16))
    email: Mapped[str | None] = mapped_column(String(254), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    totp_secret: Mapped[str] = mapped_column(String(255))  # chiffré AES-256-GCM (ADR-0006)
    recovery_codes: Mapped[list] = mapped_column(JSON, default=list)   # hachés Argon2id
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_totp_step: Mapped[int | None] = mapped_column(Integer, nullable=True)  # anti-rejeu TOTP
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    # False : compte créé par un Admin, le titulaire n'a pas encore enrôlé son application TOTP ni choisi son
    # mot de passe. Le secret TOTP est alors généré chez l'utilisateur et jamais montré à l'Admin.
    enrolled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    # Code d'activation à usage unique (haché), remis au titulaire hors de l'Admin : sans lui, personne ne peut
    # enrôler le TOTP avec le seul mot de passe temporaire.
    enroll_code_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    enroll_code_expires: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Préférences de notification dans l'interface : {"mention": true, "assignation": false, ...}
    notif_prefs: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Identité fédérée (OIDC, Keycloak) : « émetteur » et « sub » du jeton, liés à la première connexion SSO
    oidc_issuer: Mapped[str | None] = mapped_column(String(300), nullable=True)
    oidc_sub: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Clé d'API VirusTotal personnelle (ADR-0022) : chiffrée AES-256-GCM, contexte « vt_api_key:<id> ». Jamais
    # renvoyée par l'API, jamais journalisée ; l'Admin n'en voit rien.
    vt_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    tenants: Mapped[list["Tenant"]] = relationship(secondary="user_tenants")


class OidcFlow(Base):
    """Connexion SSO en cours : état, nonce et vérificateur PKCE, à usage unique et de courte durée. [RFC 7636, RFC 9700]"""
    __tablename__ = "oidc_flows"
    state_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider: Mapped[str] = mapped_column(String(40))
    nonce: Mapped[str] = mapped_column(String(64))
    code_verifier: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class UserTenant(Base):
    """Affectation d'un utilisateur à un client (besoin d'en connaître). [PDIS IV.3.9.g, PRIS IV.3.d]"""
    __tablename__ = "user_tenants"
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)


class Session(Base):
    """Session navigateur. stage = 'password' (1er facteur validé) puis 'full' (2FA validée)."""
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    stage: Mapped[str] = mapped_column(String(16))
    csrf_token: Mapped[str] = mapped_column(String(64))
    webauthn_challenge: Mapped[str | None] = mapped_column(String(200), nullable=True)  # défi en cours (base64url)
    sso_provider: Mapped[str | None] = mapped_column(String(40), nullable=True)   # session ouverte par SSO : fournisseur
    sso_id_token: Mapped[str | None] = mapped_column(Text, nullable=True)         # jeton d'identité chiffré, pour la déconnexion unique
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ApiKey(Base):
    """Clé d'ingestion d'un manager Wazuh, rattachée à un client. Stockée hachée (SHA-256)."""
    __tablename__ = "api_keys"
    id: Mapped[str] = _id()
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(120))
    prefix: Mapped[str] = mapped_column(String(12))
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Ticket(Base):
    """Ticket d'incident. Contenu minimal exigé par PDIS IV.2.1.w."""
    __tablename__ = "tickets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "seq"),
        Index("ix_ticket_dedup", "tenant_id", "rule_id", "agent_id", "status"),
    )
    id: Mapped[str] = _id()
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    ref: Mapped[str] = mapped_column(String(32), unique=True)
    title: Mapped[str] = mapped_column(String(500))
    body_html: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(32), default="nouveau")
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    # Criticité (automatique) vs gravité (qualifiée) [PDIS IV.2.1.q]
    criticite_initiale: Mapped[str] = mapped_column(String(16))
    gravite: Mapped[str | None] = mapped_column(String(16), nullable=True)
    verdict: Mapped[str | None] = mapped_column(String(32), nullable=True)
    dommages: Mapped[str | None] = mapped_column(String(16), nullable=True)
    importance: Mapped[str] = mapped_column(String(16), default="standard")
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    risque: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Règles déclenchées
    rule_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_level: Mapped[int] = mapped_column(Integer)
    rule_description: Mapped[str] = mapped_column(String(500))
    rule_groups: Mapped[list] = mapped_column(JSON, default=list)
    # Équipements
    agent_id: Mapped[str] = mapped_column(String(32), default="")
    agent_name: Mapped[str] = mapped_column(String(200), default="")
    agent_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # MITRE ATT&CK + provenance (wazuh | table | manuel | a_completer)
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    mitre_source: Mapped[str] = mapped_column(String(16), default="a_completer")
    classification: Mapped[list] = mapped_column(JSON, default=list)  # groupes + tags conformité
    # PDIS IV.2.1.w : niveau de classification de l'incident, version de la règle déclenchée, collecteur (manager
    # Wazuh) qui a transmis l'évènement.
    niveau_classification: Mapped[str] = mapped_column(String(40), default="Non protégé", server_default="Non protégé")
    rule_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    collecteur: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Suivi par le client (PDIS IV.2.3.l) : état du ticket de son côté et demande de clôture ou de réouverture,
    # que l'équipe accepte (par le statut) ou refuse. La qualification et la clôture restent à l'équipe.
    etat_client: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Réponse aux incidents (PRIS) : compréhension structurée de l'incident (VI.5.3.e), posture et niveau de
    # discrétion vis-à-vis de l'attaquant (VI.3.b), cadre du rapport d'analyse (VI.7). Voir keryx/pris.py.
    pris: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Ce que le client lit en premier (portail client) : un titre en mots de client et le résumé « Ce qui se passe »,
    # écrits par l'équipe ; à défaut, le titre Wazuh. Distincts de la description technique.
    titre_client: Mapped[str | None] = mapped_column(String(300), nullable=True)
    resume_client: Mapped[str | None] = mapped_column(Text, nullable=True)
    resume_client_le: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    demande_client: Mapped[str | None] = mapped_column(String(16), nullable=True)
    etat_client_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    rex_required: Mapped[bool] = mapped_column(Boolean, default=False)
    # Synthèse évolutive de l'incident [PRIS VI.5.3.e]
    compromission_initiale: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    chronologie: Mapped[str | None] = mapped_column(Text, nullable=True)
    mode_operatoire: Mapped[str | None] = mapped_column(Text, nullable=True)
    perimetre: Mapped[str | None] = mapped_column(Text, nullable=True)
    rex_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    assignee_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    qualified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Acquittement (ADR-0032) : première action humaine de l'équipe (prise en charge, affectation, statut,
    # qualification). Le délai d'acquittement va de la détection Wazuh à cet instant. Une consultation n'acquitte pas.
    acquitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    acquitted_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Astreinte (ADR-0032) : heure à laquelle l'astreinte a été prévenue, puis l'escalade (une seule fois).
    astreinte_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    escalade_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Mode « crise » [PRIS VI.5.5.1] : registre des décisions, plan d'action, synthèse de crise
    crisis: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    crisis_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Classification ETSI GS ISI 002 (modèle d'événement) : axes qui décrivent l'incident, voir keryx/isi.py
    isi: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class RawAlert(Base):
    """Alerte Wazuh brute, conservée telle quelle comme contexte du ticket. [PDIS IV.2.1.aa, IV.2.2.s]"""
    __tablename__ = "raw_alerts"
    id: Mapped[str] = _id()
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    wazuh_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    sha256: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    payload: Mapped[str] = mapped_column(Text)


class Comment(Base):
    """Commentaire : interne ou visible par le client. [PDIS IV.2.3.l portail, IV.1.g consentement]"""
    __tablename__ = "comments"
    id: Mapped[str] = _id()
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[str] = mapped_column(ForeignKey("users.id"))
    body_html: Mapped[str] = mapped_column(Text)
    visible_client: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TicketEvent(Base):
    """Registre horodaté des actions sur un ticket. [PRIS VI.5.3.d, ISO 27035]"""
    __tablename__ = "ticket_events"
    id: Mapped[str] = _id()
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    visible_client: Mapped[bool] = mapped_column(Boolean, default=False)


class Notification(Base):
    """Registre des notifications : référence du ticket uniquement. [PDIS IV.2.3.g, h, j]"""
    __tablename__ = "notifications"
    id: Mapped[str] = _id()
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    # Vide pour un message qui ne concerne pas un ticket (battement de cœur manquant ou rétabli, ADR-0032).
    ticket_id: Mapped[str | None] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    channel: Mapped[str] = mapped_column(String(16))
    recipient: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32))  # ex. non_envoye_smtp_absent (22 caractères)
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Astreinte et escalade de l'équipe (ADR-0032) : canal utilisé, motif, code de réponse du service appelé.
    canal_id: Mapped[str | None] = mapped_column(ForeignKey("canaux_astreinte.id"), nullable=True)
    motif: Mapped[str | None] = mapped_column(String(16), nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)


class OnCallChannel(Base):
    """Canal d'astreinte déclaré par l'Admin (ADR-0032) : webhook ou courriel de l'équipe. L'adresse (un webhook
    contient souvent son jeton) et le secret de signature sont chiffrés au repos ; seul un libellé est affiché."""
    __tablename__ = "canaux_astreinte"
    id: Mapped[str] = _id()
    name: Mapped[str] = mapped_column(String(80), unique=True)
    kind: Mapped[str] = mapped_column(String(24))                 # webhook_json | webhook_mattermost | webhook_teams | email
    target_enc: Mapped[str] = mapped_column(Text)
    target_label: Mapped[str] = mapped_column(String(300))
    secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    include_title: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MitreMapping(Base):
    """Table de correspondance Keryx (2e niveau de la cascade MITRE)."""
    __tablename__ = "mitre_mappings"
    id: Mapped[str] = _id()
    rule_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    rule_group: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    technique_id: Mapped[str] = mapped_column(String(16))
    technique_name: Mapped[str] = mapped_column(String(200), default="")
    tactic: Mapped[str] = mapped_column(String(120), default="")
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


ATTACHMENT_KINDS = ("fichier", "image", "preuve_externe")
SCAN_STATUS = ("non_analyse", "sain", "quarantaine", "non_analysable")
LIFECYCLE = ("conserve", "restitue", "detruit")
SENSITIVITY = TLP


class Attachment(Base):
    """Pièce jointe ou preuve, avec registre de collecte.
    [PRIS VI.5.3.c registre des informations collectées ; VI.2.4 conservation/restitution/destruction ;
    IV.3.q codes malveillants ; ISO/IEC 27037]"""
    __tablename__ = "attachments"
    id: Mapped[str] = _id()
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    filename: Mapped[str] = mapped_column(String(255))            # nom d'origine, affichage seulement
    storage_name: Mapped[str | None] = mapped_column(String(64), nullable=True)  # nom aléatoire sur disque
    content_type: Mapped[str] = mapped_column(String(100), default="application/octet-stream")
    size: Mapped[int] = mapped_column(BigInteger, default=0)  # une preuve externe (image mémoire) dépasse 2 Gio
    sha256: Mapped[str] = mapped_column(String(64))
    # Registre de collecte
    description: Mapped[str] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    method: Mapped[str] = mapped_column(String(500))
    sensitivity: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    location: Mapped[str | None] = mapped_column(String(500), nullable=True)  # preuve externe : lieu de stockage
    # Antivirus et cycle de vie
    scan_status: Mapped[str] = mapped_column(String(16), default="non_analyse")
    scan_detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    lifecycle: Mapped[str] = mapped_column(String(16), default="conserve")
    visible_client: Mapped[bool] = mapped_column(Boolean, default=False)
    uploaded_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CustodyEvent(Base):
    """Chaîne de possession : qui a déposé, consulté, téléchargé, restitué ou détruit quoi, quand et pourquoi.
    [ISO/IEC 27037, RFC 3227, PRIS VI.5.3.d]"""
    __tablename__ = "custody_events"
    id: Mapped[str] = _id()
    attachment_id: Mapped[str] = mapped_column(ForeignKey("attachments.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(String(500), default="")


HASH_SOURCES = ("piece", "preuve_externe", "alerte", "saisie")
HASH_LOOKUP_STATUS = ("trouve", "inconnu")


class HashLookup(Base):
    """Recherche d'une empreinte sur VirusTotal, rattachée à un ticket : ce qui a été demandé, par qui, quand, et le
    résumé borné de la réponse. Interne : jamais montré au client. Un échec n'est pas enregistré ici (audit seulement).
    [PRIS VI.5.3.d registre des actions ; PDIS IV.3.8.g cloisonnement ; ADR-0022]"""
    __tablename__ = "hash_lookups"
    id: Mapped[str] = _id()
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    hash: Mapped[str] = mapped_column(String(64))                  # hexadécimal en minuscules
    hash_type: Mapped[str] = mapped_column(String(8))              # sha256 | sha1
    source_type: Mapped[str] = mapped_column(String(16))           # piece | preuve_externe | alerte | saisie
    source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)   # pièce ou alerte brute ; vide en saisie
    status: Mapped[str] = mapped_column(String(16))                # trouve | inconnu (jamais « sain »)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)      # résumé borné, texte assaini (voir virustotal.summarize)
    actor: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WazuhAgent(Base):
    """Dernier état connu d'un agent Wazuh d'un client, tel que l'API du manager l'a renvoyé au dernier relevé.
    [ADR-0030 ; PDIS IV.3.8.g cloisonnement : un agent appartient à un seul client]"""
    __tablename__ = "wazuh_agents"
    __table_args__ = (UniqueConstraint("tenant_id", "agent_id", name="uq_wazuh_agent"),)
    id: Mapped[str] = _id()
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(200))
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(120), nullable=True)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)      # « 4.12.0 », sans le préfixe « Wazuh v »
    status: Mapped[str] = mapped_column(String(20))      # active | disconnected | never_connected | pending
    groups: Mapped[list] = mapped_column(JSON, default=list)
    node: Mapped[str | None] = mapped_column(String(120), nullable=True)
    last_keepalive: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    registered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)   # indexeur, tous niveaux
    status_since: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)          # vu par Keryx
    missed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")   # relevés consécutifs sans cet agent
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WazuhAgentEvent(Base):
    """Historique des changements d'état d'un agent, conservé sans limite (décision du mainteneur, 24/11/2026).
    Une ligne par changement constaté par Keryx, pas par relevé. [ADR-0030]"""
    __tablename__ = "wazuh_agent_events"
    id: Mapped[str] = _id()
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    agent_id: Mapped[str] = mapped_column(String(16), index=True)
    status: Mapped[str] = mapped_column(String(20))      # nouvel état ; « removed » : agent retiré de Wazuh
    previous: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Manager d'origine (adresse de son API) : les numéros d'agent ne sont uniques que par manager ; l'historique d'un
    # autre manager n'est jamais mêlé à celui du manager courant.
    source: Mapped[str] = mapped_column(String(300), default="")
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AuditEntry(Base):
    """Journal d'audit en ajout seul, chaîné par empreintes SHA-256.
    [PDIS IV.3.9.c, ISO 27002 8.15, NT journalisation ANSSI]"""
    __tablename__ = "audit_log"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    ts: Mapped[str] = mapped_column(String(32))                # RFC 3339, figé dans l'empreinte
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


LINK_KINDS = ("parent", "lie", "doublon")
INBOX_KINDS = ("assignation", "mention", "echeance", "reponse_client")


class Observable(Base):
    """Élément relevé dans une alerte du ticket (IP, hôte, compte, empreinte, domaine) : recherche par valeur et tickets
    « peut-être liés ». Cloisonné par client comme le ticket. [voir keryx/observables.py]"""
    __tablename__ = "observables"
    __table_args__ = (UniqueConstraint("ticket_id", "kind", "value"), Index("ix_observable_valeur", "tenant_id", "kind", "value"))
    id: Mapped[str] = _id()
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TicketLink(Base):
    """Lien entre deux tickets du même client (parent, lié, doublon). [ISO/IEC 27035 : regroupement d'incidents]"""
    __tablename__ = "ticket_links"
    __table_args__ = (UniqueConstraint("ticket_id", "other_id", "kind"),)
    id: Mapped[str] = _id()
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    other_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Template(Base):
    """Modèle de commentaire ou de synthèse. tenant_id vide = modèle commun à tous les clients."""
    __tablename__ = "templates"
    id: Mapped[str] = _id()
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(16))  # commentaire | synthese
    name: Mapped[str] = mapped_column(String(120))
    body_html: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InboxItem(Base):
    """Notification dans l'interface : référence du ticket et nature de l'événement, sans détail de l'incident."""
    __tablename__ = "inbox"
    __table_args__ = (UniqueConstraint("user_id", "dedup_key"),)
    id: Mapped[str] = _id()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    kind: Mapped[str] = mapped_column(String(24))
    ticket_ref: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SavedFilter(Base):
    """Filtre de liste enregistré par un utilisateur."""
    __tablename__ = "saved_filters"
    id: Mapped[str] = _id()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# Registre de crise (PRIS VI.5.5.1) : décision (arbitrage), objectif stratégique, action (objectif opérationnel, avec
# responsable et délai), synthèse de la situation, critère de sortie de crise (VI.3.g, VI.5.5.1.h), dérogation (d.iii).
CRISIS_KINDS = ("decision", "objectif", "action", "synthese", "critere_sortie", "derogation")


class CrisisEntry(Base):
    """Entrée du registre de crise d'un ticket : décision, action du plan d'action ou point de synthèse.
    [PRIS VI.5.5.1]"""
    __tablename__ = "crisis_entries"
    id: Mapped[str] = _id()
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))
    body: Mapped[str] = mapped_column(Text)
    owner: Mapped[str | None] = mapped_column(String(120), nullable=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    done: Mapped[bool] = mapped_column(Boolean, default=False)
    # PRIS VI.5.5.1.e, j : objectif stratégique de rattachement d'une action, arbitrage qui l'a permise et entité
    # responsable de l'arbitrage ; risque associé à une dérogation ; validation par la cellule de crise stratégique.
    parent_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    decision_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    entite: Mapped[str | None] = mapped_column(String(200), nullable=True)
    risque: Mapped[str | None] = mapped_column(Text, nullable=True)
    valide_par: Mapped[str | None] = mapped_column(String(200), nullable=True)
    valide_le: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MitreTechnique(Base):
    """Référentiel MITRE ATT&CK importé (STIX 2.1) : nom et tactiques d'une technique."""
    __tablename__ = "mitre_techniques"
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SystemSetting(Base):
    """Réglage global de l'instance, modifiable par l'Admin (ex. durée de rétention par défaut). Absent = valeur par défaut."""
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="")


class RateHit(Base):
    """Passage compté par une limite de débit partagée (plusieurs processus ou conteneurs). [ADR-0010]"""
    __tablename__ = "rate_hits"
    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    key: Mapped[str] = mapped_column(String(200), index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class WebAuthnCredential(Base):
    """Clé de sécurité WebAuthn / FIDO2, second facteur en option à la place du TOTP. [RFC 8809 ; W3C WebAuthn]
    La clé publique ne permet pas de se connecter : seul l'authentificateur détient la clé privée."""
    __tablename__ = "webauthn_credentials"
    id: Mapped[str] = _id()
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[str] = mapped_column(String(512), unique=True)   # base64url
    public_key: Mapped[str] = mapped_column(Text)                          # base64url (COSE)
    sign_count: Mapped[int] = mapped_column(BigInteger, default=0)
    name: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Timestamp(Base):
    """Jeton d'horodatage de confiance (RFC 3161) conservé avec la pièce ou le point de contrôle qu'il atteste.
    Le message horodaté est « keryx-v1:<type>:<identifiant>:<empreinte> » : il lie le type, l'objet et son empreinte."""
    __tablename__ = "timestamps"
    id: Mapped[str] = _id()
    object_type: Mapped[str] = mapped_column(String(24))      # attachment | audit
    object_id: Mapped[str] = mapped_column(String(64), index=True)
    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True, index=True)
    message: Mapped[str] = mapped_column(String(300))
    token: Mapped[bytes] = mapped_column(LargeBinary)          # réponse RFC 3161 complète (DER)
    gen_time: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    serial: Mapped[str] = mapped_column(String(80))
    tsa_url: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ActionClient(Base):
    """Action demandée au client par l'équipe (PDIS IV.2.3.l : état des actions engagées, visible et mis à jour par
    le client sur le portail)."""
    __tablename__ = "actions_client"
    id: Mapped[str] = _id()
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    libelle: Mapped[str] = mapped_column(String(500))
    etat: Mapped[str] = mapped_column(String(16), default="a_faire", server_default="a_faire")
    commentaire: Mapped[str | None] = mapped_column(Text, nullable=True)
    cree_par: Mapped[str] = mapped_column(String(64))
    cree_le: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    maj_par: Mapped[str | None] = mapped_column(String(64), nullable=True)
    maj_le: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class MesureEndiguement(Base):
    """Mesure d'endiguement ou procédure d'urgence « bouton rouge » (PRIS VI.5.4) : proposée par l'équipe, décidée
    par le commanditaire (sur le portail ou rapportée par l'équipe), appliquée puis levée ; réévaluée au fil de
    l'incident."""
    __tablename__ = "mesures_endiguement"
    id: Mapped[str] = _id()
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    type: Mapped[str] = mapped_column(String(16), default="endiguement")        # endiguement | urgence
    libelle: Mapped[str] = mapped_column(String(1000))
    etat: Mapped[str] = mapped_column(String(16), default="proposee")           # proposee | acceptee | refusee | appliquee | levee
    decision_par: Mapped[str | None] = mapped_column(String(200), nullable=True)
    commentaire: Mapped[str | None] = mapped_column(Text, nullable=True)
    cree_par: Mapped[str] = mapped_column(String(64))
    cree_le: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    maj_par: Mapped[str | None] = mapped_column(String(64), nullable=True)
    maj_le: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
