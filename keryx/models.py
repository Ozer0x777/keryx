"""Modèle de données Keryx.

Chaque table indique entre crochets les exigences qu'elle sert.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
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
TLP = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")  # FIRST TLP 2.0


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
    # Délais cibles par gravité, en heures : {"Critique": {"qualification": 1, "resolution": 8}, ...}
    sla: Mapped[dict | None] = mapped_column(JSON, nullable=True)
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
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    # Préférences de notification dans l'interface : {"mention": true, "assignation": false, ...}
    notif_prefs: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tenants: Mapped[list["Tenant"]] = relationship(secondary="user_tenants")


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
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Mode « crise » [PRIS VI.5.5.1] : registre des décisions, plan d'action, synthèse de crise
    crisis: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    crisis_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    ticket_id: Mapped[str] = mapped_column(ForeignKey("tickets.id", ondelete="CASCADE"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    channel: Mapped[str] = mapped_column(String(16))
    recipient: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")


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
SCAN_STATUS = ("non_analyse", "sain", "quarantaine")
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
    size: Mapped[int] = mapped_column(Integer, default=0)
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


CRISIS_KINDS = ("decision", "action", "synthese")


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
    created_by: Mapped[str] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MitreTechnique(Base):
    """Référentiel MITRE ATT&CK importé (STIX 2.1) : nom et tactiques d'une technique."""
    __tablename__ = "mitre_techniques"
    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    tactics: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
