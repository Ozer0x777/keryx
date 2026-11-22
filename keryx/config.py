"""Configuration par variables d'environnement (aucune valeur secrète en dur)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


# Rétention minimale des alertes brutes [PDIS IV.2.2.w : 6 mois minimum, texte non revérifié ici] : plancher ET valeur par défaut.
MIN_RETENTION_MONTHS = 6


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
    # Corps de requête ordinaire (JSON) : borne appliquée avant toute lecture, session ouverte ou non (voir bodylimit.py)
    max_body_bytes: int = field(default_factory=lambda: _int("KERYX_MAX_BODY_BYTES", 2 * 1024 * 1024))

    # Sessions et authentification (RFC 6265, ASVS V6/V7)
    cookie_secure: bool = field(default_factory=lambda: _bool("KERYX_COOKIE_SECURE", True))
    session_hours: int = field(default_factory=lambda: _int("KERYX_SESSION_HOURS", 8))
    max_failed_logins: int = 5
    # Tentatives de connexion par adresse IP et par 5 minutes. À relever derrière un proxy partagé (ADR-0010).
    login_user_limit: int = field(default_factory=lambda: _int("KERYX_LOGIN_USER_LIMIT", 10))
    login_ip_limit: int = field(default_factory=lambda: _int("KERYX_LOGIN_IP_LIMIT", 30))
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
    # Mot de passe de l'archive de quarantaine (convention du métier : « infected »). Il ne protège pas un secret :
    # il empêche l'ouverture accidentelle et l'analyse automatique du fichier par un poste ou une messagerie.
    quarantine_password: str = field(default_factory=lambda: os.environ.get("KERYX_QUARANTINE_PASSWORD", "infected"))
    # Stockage des pièces : « disk » (dossier local) ou « s3 » (stockage objet compatible S3, chiffré avant envoi).
    storage_backend: str = field(default_factory=lambda: os.environ.get("KERYX_STORAGE", "disk"))
    s3_endpoint: str | None = field(default_factory=lambda: os.environ.get("KERYX_S3_ENDPOINT"))
    s3_bucket: str | None = field(default_factory=lambda: os.environ.get("KERYX_S3_BUCKET"))
    s3_access_key: str | None = field(default_factory=lambda: os.environ.get("KERYX_S3_ACCESS_KEY"))
    s3_secret_key: str | None = field(default_factory=lambda: os.environ.get("KERYX_S3_SECRET_KEY"))
    s3_region: str = field(default_factory=lambda: os.environ.get("KERYX_S3_REGION", "us-east-1"))
    s3_prefix: str = field(default_factory=lambda: os.environ.get("KERYX_S3_PREFIX", "keryx"))
    s3_allow_http: bool = field(default_factory=lambda: _bool("KERYX_S3_ALLOW_HTTP", False))
    # Sans ClamAV : les fichiers sont acceptés mais marqués « non analysé » (jamais présentés comme sains).

    # Journal d'audit vers Wazuh (RFC 5424)
    syslog_host: str | None = field(default_factory=lambda: os.environ.get("KERYX_SYSLOG_HOST"))
    syslog_port: int = field(default_factory=lambda: _int("KERYX_SYSLOG_PORT", 514))
    hostname: str = field(default_factory=lambda: os.environ.get("KERYX_HOSTNAME", "keryx"))

    # Limites de débit : « memory » (par processus) ou « db » (partagées entre processus, base commune).
    # Par défaut : partagées dès que la base est PostgreSQL.
    rate_limit_backend: str | None = field(default_factory=lambda: os.environ.get("KERYX_RATE_LIMIT_BACKEND"))

    # Rétention des alertes brutes des tickets clos, en mois (PDIS IV.2.2.w : 6 mois minimum ; ISM : 12 mois).
    # À valider avec le DPO ; chaque client peut avoir sa propre valeur.
    retention_months: int = field(default_factory=lambda: max(MIN_RETENTION_MONTHS, _int("KERYX_RETENTION_MONTHS", MIN_RETENTION_MONTHS)))

    # Authentification unique OIDC (Keycloak). JSON : [{"name":"soc","label":"Compte SOC","issuer":"https://…/realms/soc",
    # "client_id":"keryx","client_secret":"…"}]. Plusieurs fournisseurs possibles (realms « soc » et « clients »).
    oidc_providers: str | None = field(default_factory=lambda: os.environ.get("KERYX_OIDC_PROVIDERS"))
    # HTTP autorisé pour l'émetteur : essais locaux uniquement (en production : HTTPS obligatoire)
    oidc_allow_http: bool = field(default_factory=lambda: _bool("KERYX_OIDC_ALLOW_HTTP", False))
    # Si vrai, seul un Admin peut encore se connecter par mot de passe local (accès de secours) ; les autres passent par SSO.
    oidc_enforce: bool = field(default_factory=lambda: _bool("KERYX_OIDC_ENFORCE", False))
    # Exige cette valeur dans la revendication « acr » du jeton (ex. niveau d'authentification MFA du realm). Vide = non contrôlé.
    oidc_required_acr: str | None = field(default_factory=lambda: os.environ.get("KERYX_OIDC_REQUIRED_ACR"))

    # Horodatage de confiance RFC 3161 : URL de l'autorité d'horodatage (à choisir dans l'UE) et fichier PEM de ses
    # certificats d'autorité (racine, et intermédiaires éventuels). Désactivé si l'URL est vide.
    tsa_url: str | None = field(default_factory=lambda: os.environ.get("KERYX_TSA_URL") or None)
    tsa_ca_file: str | None = field(default_factory=lambda: os.environ.get("KERYX_TSA_CA_FILE") or None)
    # Authentification auprès de l'autorité (les prestataires qualifiés l'exigent presque toujours) : identifiant et mot de
    # passe (HTTP Basic), OU jeton (Bearer), OU certificat client (TLS mutuel) ; et politique d'horodatage attendue (OID).
    tsa_user: str | None = field(default_factory=lambda: os.environ.get("KERYX_TSA_USER") or None)
    tsa_password: str | None = field(default_factory=lambda: os.environ.get("KERYX_TSA_PASSWORD") or None)
    tsa_bearer: str | None = field(default_factory=lambda: os.environ.get("KERYX_TSA_BEARER") or None)
    tsa_client_cert: str | None = field(default_factory=lambda: os.environ.get("KERYX_TSA_CLIENT_CERT") or None)
    tsa_client_key: str | None = field(default_factory=lambda: os.environ.get("KERYX_TSA_CLIENT_KEY") or None)
    tsa_policy_oid: str | None = field(default_factory=lambda: os.environ.get("KERYX_TSA_POLICY_OID") or None)

    # Contexte Wazuh (ADR-0021) : lecture de l'indexeur d'un client. Les adresses et le compte se règlent par client
    # (Administration > Clients). Ici : la boucle locale n'est acceptée comme destination que sur demande explicite
    # (essais, indexeur sur la même machine), et le champ de date des alertes (à confirmer sur un vrai Wazuh).
    wazuh_allow_loopback: bool = field(default_factory=lambda: _bool("KERYX_WAZUH_ALLOW_LOOPBACK", False))
    wazuh_time_field: str = field(default_factory=lambda: os.environ.get("KERYX_WAZUH_TIME_FIELD") or "@timestamp")
    # Récupérations de contexte par minute : par analyste, et par client (protège l'indexeur).
    wazuh_context_user_limit: int = field(default_factory=lambda: _int("KERYX_WAZUH_CONTEXT_USER_LIMIT", 20))
    wazuh_context_client_limit: int = field(default_factory=lambda: _int("KERYX_WAZUH_CONTEXT_CLIENT_LIMIT", 60))

    # Interface web (fichiers construits par Vite)
    web_dist: str = field(default_factory=lambda: os.environ.get(
        "KERYX_WEB_DIST", os.path.join(os.path.dirname(__file__), "web_dist")))
