"""Configuration par variables d'environnement (aucune valeur secrète en dur)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    return int(os.environ.get(name, str(default)))


@dataclass
class Settings:
    # SQLite pour les tests, PostgreSQL en production (ADR-0002).
    database_url: str = field(default_factory=lambda: os.environ.get("KERYX_DATABASE_URL", "sqlite:///./keryx.db"))
    # Création directe du schéma : réservée aux tests. En déploiement, `alembic upgrade head` (ADR-0005).
    auto_create_schema: bool = field(default_factory=lambda: _bool("KERYX_AUTO_CREATE_SCHEMA", False))
    # Clé de chiffrement des secrets au repos (secrets TOTP) : 32 octets en base64 (ADR-0006).
    secret_key: str | None = field(default_factory=lambda: os.environ.get("KERYX_SECRET_KEY"))

    # Ingestion Wazuh
    min_rule_level: int = field(default_factory=lambda: _int("KERYX_MIN_RULE_LEVEL", 7))
    dedup_minutes: int = field(default_factory=lambda: _int("KERYX_DEDUP_MINUTES", 15))
    max_alert_bytes: int = 1_000_000

    # Sessions et authentification (RFC 6265, ASVS V6/V7)
    cookie_secure: bool = field(default_factory=lambda: _bool("KERYX_COOKIE_SECURE", True))
    session_hours: int = field(default_factory=lambda: _int("KERYX_SESSION_HOURS", 8))
    max_failed_logins: int = 5
    lockout_minutes: int = 15

    # Notifications : référence + lien uniquement (PDIS IV.2.3.g)
    public_url: str = field(default_factory=lambda: os.environ.get("KERYX_PUBLIC_URL", "https://keryx.local"))
    smtp_host: str | None = field(default_factory=lambda: os.environ.get("KERYX_SMTP_HOST"))
    smtp_port: int = field(default_factory=lambda: _int("KERYX_SMTP_PORT", 587))
    smtp_tls: str = field(default_factory=lambda: os.environ.get("KERYX_SMTP_TLS", "starttls"))  # starttls | ssl
    smtp_user: str | None = field(default_factory=lambda: os.environ.get("KERYX_SMTP_USER"))
    smtp_password: str | None = field(default_factory=lambda: os.environ.get("KERYX_SMTP_PASSWORD"))
    smtp_from: str = field(default_factory=lambda: os.environ.get("KERYX_SMTP_FROM", "keryx@keryx.local"))
    smtp_timeout_s: int = 10
    # Nouvelle tentative des courriels en échec : intervalle de relance en secondes (0 = désactivée), essais maximum.
    notify_retry_interval_s: int = field(default_factory=lambda: _int("KERYX_NOTIFY_RETRY_S", 300))
    notify_max_attempts: int = 5

    # Pièces jointes (PRIS VI.5.3.c, VI.2.4, IV.3.q)
    attachments_dir: str = field(default_factory=lambda: os.environ.get("KERYX_ATTACHMENTS_DIR", "./data/attachments"))
    max_attachment_bytes: int = 20 * 1024 * 1024
    clamav_host: str | None = field(default_factory=lambda: os.environ.get("KERYX_CLAMAV_HOST"))
    clamav_port: int = field(default_factory=lambda: _int("KERYX_CLAMAV_PORT", 3310))
    # Sans ClamAV : les fichiers sont acceptés mais marqués « non analysé » (jamais présentés comme sains).

    # Journal d'audit vers Wazuh (RFC 5424)
    syslog_host: str | None = field(default_factory=lambda: os.environ.get("KERYX_SYSLOG_HOST"))
    syslog_port: int = field(default_factory=lambda: _int("KERYX_SYSLOG_PORT", 514))
    hostname: str = field(default_factory=lambda: os.environ.get("KERYX_HOSTNAME", "keryx"))

    # Rétention des alertes brutes des tickets clos, en mois (PDIS IV.2.2.w : 6 mois minimum ; ISM : 12 mois).
    # À valider avec le DPO ; chaque client peut avoir sa propre valeur.
    retention_months: int = field(default_factory=lambda: max(6, _int("KERYX_RETENTION_MONTHS", 12)))

    # Interface web (fichiers construits par Vite)
    web_dist: str = field(default_factory=lambda: os.environ.get(
        "KERYX_WEB_DIST", os.path.join(os.path.dirname(__file__), "web_dist")))
