"""Administration en ligne de commande (actions tracées dans le journal d'audit).

Exemples :
  python -m keryx.cli init-db
  python -m keryx.cli add-client ACME "ACME Industrie"
  python -m keryx.cli add-user sbenali "S. Benali" analyst --clients ACME
  python -m keryx.cli add-user admin "Administrateur" admin --activation   # premier compte : code d'activation
  python -m keryx.cli add-api-key ACME wazuh-manager-01
  python -m keryx.cli add-mitre --group authentication_failures T1110 "Brute Force" "Credential Access"
  python -m keryx.cli verify-audit [--checkpoint SEQ:SCEAU]
  python -m keryx.cli checkpoint             # sceau de tête à archiver hors de Keryx
  python -m keryx.cli set-contacts ACME rssi@acme.example soc@acme.example
  python -m keryx.cli gen-key                # nouvelle KERYX_SECRET_KEY
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys

from sqlalchemy import select

from . import audit, security
from .config import Settings
from .db import Base, make_engine, make_session_factory
from .mitre import valid_technique
from .models import ROLES, ApiKey, MitreMapping, Tenant, User


def _session(settings: Settings):
    engine = make_engine(settings.database_url)
    if settings.auto_create_schema:
        Base.metadata.create_all(engine)
    return make_session_factory(engine)()


def _trace(db, settings: Settings, actor: str, action: str, details: dict) -> None:
    """Inscrit une opération d'exploitation (sauvegarde, restauration) au journal d'audit de l'instance courante.
    Une restauration peut être lancée sur une machine sans base Keryx (reprise après sinistre) : dans ce cas l'opération
    réussit quand même, et l'absence de trace est signalée au lieu de créer une base vide."""
    from sqlalchemy.exc import SQLAlchemyError
    url = settings.database_url
    try:
        if url.startswith("sqlite:///") and not os.path.isfile(url[len("sqlite:///"):]):
            raise FileNotFoundError(url)
        audit.record(db, actor, action, None, None, None, details)
        db.commit()
    except (SQLAlchemyError, OSError):
        db.rollback()
        print(f"Avertissement : « {action} » n'a pas pu être inscrite au journal d'audit (base de l'instance courante "
              "absente ou injoignable).", file=sys.stderr)


_OPEN: list = []   # sessions ouvertes par une commande, fermées à sa fin (utile quand main() est appelée dans un processus qui continue)


# Jeu de démonstration : alertes fictives (règles, agents et adresses inventés, plages d'adresses de documentation
# RFC 5737 pour l'extérieur), passées par la même ingestion que les vraies alertes. Niveau, règle, description, agent,
# adresse, importance de l'équipement, techniques MITRE fournies par la « règle ».
DEMO_ALERTS = [
    (7, "5503", "Échecs d'ouverture de session SSH en série", "srv-web-01", "10.20.1.15", "standard", ["T1110"]),
    (15, "100900", "Exfiltration corrélée vers une adresse externe", "srv-fichiers-02", "10.20.3.32", "standard", []),
    (9, "92201", "Exécution de PowerShell encodé depuis un processus Office", "pc-compta-07", "10.20.5.41", "standard", ["T1059.001"]),
    (7, "554", "Fichier ajouté dans un répertoire surveillé", "srv-web-01", "10.20.1.15", "standard", []),
    (10, "31151", "Balayage web : nombreuses erreurs 400 depuis une même source", "srv-web-01", "10.20.1.15", "standard", ["T1595"]),
    (7, "60122", "Échecs d'ouverture de session Windows en série", "srv-ad-01", "10.20.0.10", "vital", ["T1110.003"]),
    (7, "100210", "Accès à un partage RH en dehors du périmètre habituel", "srv-fichiers-02", "10.20.3.32", "sensible", []),
    (12, "52502", "Fichier reconnu malveillant par l'intégration antivirus", "pc-compta-07", "10.20.5.41", "sensible", ["T1204.002"]),
    (8, "5402", "Élévation de privilèges par sudo vers root", "srv-bdd-01", "10.20.2.20", "sensible", ["T1548.003"]),
    (10, "100320", "Désactivation de la journalisation d'audit", "srv-bdd-01", "10.20.2.20", "vital", ["T1562.001"]),
]


def _demo(db, settings, actor: str) -> int:
    from datetime import timedelta
    from .ids import utcnow
    from .ingest import AlertRejected, ingest_alert
    if db.scalars(select(Tenant).where(Tenant.key == "DEMO")).first() is not None:
        print("Le client DEMO existe déjà : rien n'a été créé (le supprimer d'abord pour recommencer).", file=sys.stderr)
        return 2
    tenant = Tenant(key="DEMO", name="Démonstration (données fictives)")
    db.add(tenant); db.flush()
    audit.record(db, actor, "client.create", "tenant", "DEMO", tenant.id, {"demo": True})
    start = utcnow() - timedelta(hours=6)
    refs = []
    for n, (level, rule_id, desc, agent, ip, imp, mitre) in enumerate(DEMO_ALERTS):
        when = start + timedelta(minutes=35 * n)
        alert = {
            "id": f"demo-{n + 1}", "timestamp": when.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
            "rule": {"id": rule_id, "level": level, "description": desc, "groups": ["demo"],
                     **({"mitre": {"id": mitre, "tactic": [], "technique": []}} if mitre else {})},
            "agent": {"id": f"{90 + n:03d}", "name": agent, "ip": ip, "labels": {"importance": imp}},
            "location": "/var/log/demo.log", "decoder": {"name": "demo"},
            "data": {"srcip": "203.0.113.77"} if rule_id == "100900" else {},
            "full_log": "Données fictives : jeu de démonstration de Keryx.",
        }
        try:
            r = ingest_alert(db, settings, tenant, alert, actor)
        except AlertRejected as exc:
            db.rollback()
            print(f"Alerte de démonstration refusée : {exc}", file=sys.stderr)
            return 1
        if r.ticket is not None:
            refs.append(r.ticket.ref)
    db.commit()
    print(f"Client DEMO créé avec {len(refs)} incidents fictifs : {', '.join(refs)}.")
    print("Pour les voir : rattacher un compte d'analyste au client DEMO (Administration, Comptes).")
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    finally:
        while _OPEN:
            _OPEN.pop().close()


def _main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="keryx")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db")
    c = sub.add_parser("add-client"); c.add_argument("key"); c.add_argument("name")
    sub.add_parser("purge", help="Supprime les alertes brutes arrivées en fin de rétention (--apply pour exécuter)").add_argument(
        "--apply", action="store_true")
    ex = sub.add_parser("export-client", help="Restitution : toutes les données d'un client dans une archive ZIP (PDIS IV.5.2.b)")
    ex.add_argument("client"); ex.add_argument("out")
    de = sub.add_parser("destroy-client", help="Fin de prestation : détruit toutes les données d'un client (PDIS IV.5.2.f), "
                                               "après un export ; simulation sans --confirm")
    de.add_argument("client"); de.add_argument("--confirm", metavar="CLE", help="répéter la clé du client pour exécuter")
    sub.add_parser("backup", help="Sauvegarde chiffrée (base SQLite + pièces)").add_argument("out")
    r = sub.add_parser("restore", help="Restaure une sauvegarde dans un dossier vide et vérifie l'audit")
    r.add_argument("file"); r.add_argument("--to", required=True)
    r.add_argument("--pg-url", help="PostgreSQL : URL d'une base VIDE où restaurer (sauvegarde PostgreSQL)")
    sub.add_parser("migrate-attachments", help="Copie les pièces du disque vers le stockage objet (KERYX_STORAGE=s3 à configurer), avec vérification").add_argument(
        "--dry-run", action="store_true")
    sub.add_parser("tsa-check", help="Essaie l'autorité d'horodatage configurée (demande, vérification, politique, certificat)")
    sub.add_parser("import-mitre", help="Importe le référentiel ATT&CK (fichier STIX 2.1)").add_argument("file")
    u = sub.add_parser("add-user")
    u.add_argument("username"); u.add_argument("display_name"); u.add_argument("role", choices=ROLES)
    u.add_argument("--clients", default="", help="clés clients séparées par des virgules")
    u.add_argument("--password-stdin", action="store_true",
                   help="lit le mot de passe sur l'entrée standard (sans terminal, par ex. depuis un script ou docker exec). "
                        "Sinon : variable d'environnement KERYX_NEW_PASSWORD, ou saisie interactive")
    u.add_argument("--activation", action="store_true",
                   help="compte à activer par son titulaire : le mot de passe est temporaire, un code d'activation "
                        "(usage unique, 72 h) est affiché une fois, le TOTP est enrôlé à la première connexion")
    k = sub.add_parser("add-api-key"); k.add_argument("client_key"); k.add_argument("name")
    m = sub.add_parser("add-mitre")
    g = m.add_mutually_exclusive_group(required=True)
    g.add_argument("--rule"); g.add_argument("--group")
    m.add_argument("technique"); m.add_argument("name", nargs="?", default=""); m.add_argument("tactic", nargs="?", default="")
    va = sub.add_parser("verify-audit"); va.add_argument("--checkpoint")
    sub.add_parser("checkpoint")
    sc = sub.add_parser("set-contacts"); sc.add_argument("client_key"); sc.add_argument("emails", nargs="*")
    sub.add_parser("gen-key")
    sub.add_parser("demo", help="Crée le client DEMO et dix incidents fictifs, pour essayer Keryx sans Wazuh")
    args = p.parse_args(argv)

    if args.cmd == "gen-key":
        print(security.new_secret_key())
        return 0

    settings = Settings()
    box = security.SecretBox(settings.secret_key)
    audit.configure(settings.secret_key)
    db = _session(settings)
    _OPEN.append(db)
    actor = f"cli:{os.environ.get('USER', 'admin')}"

    if args.cmd == "init-db":
        print("Base initialisée :", settings.database_url)
        return 0

    if args.cmd == "add-client":
        key = args.key.upper()
        if not key.isalnum() or len(key) > 16:
            print("La clé client doit être alphanumérique (16 caractères max).", file=sys.stderr)
            return 2
        t = Tenant(key=key, name=args.name)
        db.add(t); db.flush()
        audit.record(db, actor, "client.create", "tenant", key, t.id)
        db.commit()
        print(f"Client {key} créé.")
        return 0

    if args.cmd == "add-user":
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        else:
            password = os.environ.get("KERYX_NEW_PASSWORD") or ""
            if not password:
                if not sys.stdin.isatty():
                    print("Aucun terminal pour saisir le mot de passe : utilisez la variable d'environnement "
                          "KERYX_NEW_PASSWORD ou l'option --password-stdin.", file=sys.stderr)
                    return 2
                password = getpass.getpass("Mot de passe (12 caractères min.) : ")
        if not password:
            print("Mot de passe vide.", file=sys.stderr)
            return 2
        tenants = []
        for key in filter(None, (x.strip().upper() for x in args.clients.split(","))):
            t = db.scalars(select(Tenant).where(Tenant.key == key)).first()
            if t is None:
                print(f"Client inconnu : {key}", file=sys.stderr)
                return 2
            tenants.append(t)
        if args.role == "client" and len(tenants) != 1:
            print("Un compte Client doit être rattaché à exactement un client.", file=sys.stderr)
            return 2
        if args.role == "admin" and tenants:
            print("Un compte Admin n'est rattaché à aucun client (séparation admin / opérateurs).", file=sys.stderr)
            return 2
        if db.scalars(select(User).where(User.username == args.username)).first() is not None:
            print(f"L'identifiant {args.username} existe déjà.", file=sys.stderr)
            return 2
        if args.activation:
            # Même parcours qu'un compte créé dans l'interface (routes_admin.users_create) : aucun secret TOTP n'est
            # généré ni affiché ici, le titulaire l'enrôle dans son navigateur et choisit son mot de passe.
            import secrets
            from datetime import timedelta
            from .ids import utcnow
            code = secrets.token_urlsafe(12)
            user = User(username=args.username, display_name=args.display_name, role=args.role,
                        password_hash=security.hash_password(password), totp_secret="", recovery_codes=[],
                        enrolled=False, enroll_code_hash=security.sha256(code),
                        enroll_code_expires=utcnow() + timedelta(hours=72), tenants=tenants)
            db.add(user); db.flush()
            audit.record(db, actor, "user.create", "user", user.id, None,
                         {"role": args.role, "clients": [t.key for t in tenants], "activation": "cli"})
            db.commit()
            print(f"Utilisateur {args.username} créé ({args.role}), à activer à la première connexion.")
            print(f"Code d'activation (affiché une seule fois, valable 72 h) :\n  {code}")
            return 0
        secret = security.new_totp_secret()
        plain_codes, hashed_codes = security.new_recovery_codes()
        user = User(username=args.username, display_name=args.display_name, role=args.role,
                    password_hash=security.hash_password(password), totp_secret="",
                    recovery_codes=hashed_codes, tenants=tenants)
        db.add(user); db.flush()
        user.totp_secret = box.encrypt(secret, f"totp:{user.id}")
        audit.record(db, actor, "user.create", "user", user.id, None, {"role": args.role,
                                                                        "clients": [t.key for t in tenants]})
        db.commit()
        print(f"Utilisateur {args.username} créé ({args.role}).")
        print("À enregistrer dans l'application d'authentification (une seule fois) :")
        print("  ", security.totp_uri(secret, args.username))
        print("Codes de secours (affichés une seule fois) :")
        for code in plain_codes:
            print("  ", code)
        return 0

    if args.cmd == "demo":
        return _demo(db, settings, actor)

    if args.cmd == "add-api-key":
        t = db.scalars(select(Tenant).where(Tenant.key == args.client_key.upper())).first()
        if t is None:
            print("Client inconnu.", file=sys.stderr)
            return 2
        key, prefix, digest = security.new_api_key()
        db.add(ApiKey(tenant_id=t.id, name=args.name, prefix=prefix, key_hash=digest))
        audit.record(db, actor, "apikey.create", "tenant", t.key, t.id, {"name": args.name, "prefix": prefix})
        db.commit()
        print(f"Clé d'ingestion pour {t.key} (affichée une seule fois) :\n  {key}")
        return 0

    if args.cmd == "add-mitre":
        if not valid_technique(args.technique):
            print("Identifiant MITRE invalide (ex. T1110 ou T1543.003).", file=sys.stderr)
            return 2
        db.add(MitreMapping(rule_id=args.rule, rule_group=args.group, technique_id=args.technique,
                            technique_name=args.name, tactic=args.tactic, created_by=actor))
        audit.record(db, actor, "mitre.mapping_create", None, args.technique, None,
                     {"rule": args.rule, "group": args.group})
        db.commit()
        print("Correspondance ajoutée.")
        return 0

    if args.cmd == "set-contacts":
        t = db.scalars(select(Tenant).where(Tenant.key == args.client_key.upper())).first()
        if t is None:
            print("Client inconnu.", file=sys.stderr)
            return 2
        emails = [e for e in args.emails if "@" in e and len(e) <= 254]
        t.contact_emails = emails
        audit.record(db, actor, "client.contacts", "tenant", t.key, t.id, {"count": len(emails)})
        db.commit()
        print(f"{len(emails)} contact(s) enregistré(s) pour {t.key}.")
        return 0

    if args.cmd == "backup":
        from . import backup
        try:
            info = backup.create(settings.database_url, None if settings.storage_backend == "s3" else settings.attachments_dir,
                                 settings.secret_key, args.out)
        except backup.BackupError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        # Tracée après coup : la sauvegarde elle-même ne contient donc pas cette entrée.
        _trace(db, settings, actor, "backup.create", {"fichier": os.path.basename(args.out), "fichiers": info["files"]})
        print(f"Sauvegarde chiffrée écrite dans {args.out} ({info['files']} fichiers). Conserver KERYX_SECRET_KEY à part.")
        if settings.storage_backend == "s3":
            print("Les pièces sont dans le stockage objet : à sauvegarder avec les outils du serveur d'objets (réplication, versions).")
        return 0

    if args.cmd == "restore":
        from . import backup
        try:
            info = backup.restore(args.file, settings.secret_key, args.to, pg_restore_url=args.pg_url)
        except backup.BackupError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        # Tracée dans le journal de l'instance courante (KERYX_DATABASE_URL), jamais dans la base restaurée, qui reste
        # identique à la sauvegarde.
        details = {"fichier": os.path.basename(args.file), "fichiers": info["files"], "postgres": bool(info["postgres"])}
        if info["postgres"] and not args.pg_url:
            _trace(db, settings, actor, "backup.restore", {**details, "base_restauree": False})
            print(f"Sauvegarde PostgreSQL extraite dans {args.to}. Restaurer avec : pg_restore --no-owner -d <base vide> "
                  f"{args.to}/keryx.pgdump (ou relancer avec --pg-url).")
            return 0
        restored = Settings(database_url=args.pg_url if info["postgres"] else f"sqlite:///{args.to}/keryx.db",
                            secret_key=settings.secret_key)
        rdb = _session(restored)
        _OPEN.append(rdb)
        ok, bad = audit.verify_chain(rdb)
        rdb.rollback()
        _trace(db, settings, actor, "backup.restore", {**details, "base_restauree": True, "chaine_audit_integre": ok})
        print(f"Restauration dans {args.to} : {info['files']} fichiers, empreintes vérifiées. "
              + ("Chaîne d'audit intègre." if ok else f"CHAÎNE D'AUDIT ROMPUE à l'entrée {bad}."))
        return 0 if ok else 1

    if args.cmd == "migrate-attachments":
        from sqlalchemy import select as _select
        from . import attachments as att
        from .models import Attachment
        from .s3store import StorageError
        if settings.storage_backend != "s3":
            print("Configurer d'abord KERYX_STORAGE=s3 et KERYX_S3_* (destination).", file=sys.stderr)
            return 2
        objects = att.object_store(settings)
        done = already = missing = failed = 0
        # Tout contenu encore présent est migré : pièces conservées ET restituées (une pièce restituée garde son contenu
        # jusqu'à sa destruction, qui doit le retrouver dans le stockage objet). Seules les pièces détruites sont écartées.
        rows = db.scalars(_select(Attachment).where(Attachment.storage_name.is_not(None), Attachment.lifecycle != "detruit")).all()
        db.commit()  # fin de la transaction de lecture : la copie ne bloque pas les écritures de l'application (SQLite)
        for a in rows:
            quarantined = att.isole(a.scan_status)
            path = att._path(settings, a.storage_name, quarantined)
            key = att._object_key(objects, a.storage_name, quarantined)
            try:
                try:
                    with open(path, "rb") as f:
                        content = f.read()
                except FileNotFoundError:
                    # Absent du disque : « déjà migré » seulement si l'objet existe vraiment ; sinon le contenu est perdu.
                    if objects.exists(key):
                        already += 1
                    else:
                        missing += 1
                        print(f"MANQUANT {a.id} ({a.filename}) : ni sur le disque ni dans le stockage objet", file=sys.stderr)
                    continue
                if not args.dry_run:
                    objects.put(key, content)
                    if objects.get(key) != content:      # relecture : l'objet déchiffré doit être identique au fichier
                        raise StorageError("relecture différente")
                done += 1
            except (StorageError, OSError) as exc:        # OSError : fichier illisible, ou objet introuvable à la relecture
                failed += 1
                print(f"ÉCHEC {a.id} ({a.filename}) : {exc}", file=sys.stderr)
        audit.record(db, actor, "attachments.migrate", None, None, None,
                     {"copiees": done, "deja_migrees": already, "manquantes": missing, "echecs": failed,
                      "simulation": bool(args.dry_run)})
        db.commit()
        print(f"{done} pièce(s) copiée(s){' (simulation)' if args.dry_run else ' et relue(s)'}, {already} déjà migrée(s), "
              f"{missing} manquante(s), {failed} en échec. "
              "Les fichiers du disque ne sont PAS supprimés : les garder jusqu'à validation.")
        return 1 if failed or missing else 0

    if args.cmd == "tsa-check":
        from . import timestamping as ts
        if not settings.tsa_url:
            print("KERYX_TSA_URL non défini.", file=sys.stderr)
            return 2
        msg = ts.message_for("essai", "tsa-check", "00" * 32)
        try:
            with ts.make_client(settings) as http:
                r = ts.stamp(settings.tsa_url, msg, settings.tsa_ca_file, http=http, policy_oid=settings.tsa_policy_oid)
            when = ts.verify(r["token"], msg, settings.tsa_ca_file, settings.tsa_policy_oid)
        except ts.TimestampError as exc:
            print(f"ÉCHEC : {exc}", file=sys.stderr)
            return 1
        print(f"OK : horodatage obtenu et vérifié (chaîne jusqu'aux certificats de KERYX_TSA_CA_FILE).\n"
              f"  Heure attestée : {when.isoformat()}\n  Série          : {r['serial']}\n  Politique (OID): {r['policy']}\n"
              f"  Autorité       : {settings.tsa_url}\n  Taille du jeton: {len(r['token'])} octets")
        if not settings.tsa_policy_oid:
            print("  Conseil : fixer KERYX_TSA_POLICY_OID à l'OID ci-dessus (celui que le prestataire annonce pour son service qualifié).")
        return 0

    if args.cmd in ("export-client", "destroy-client"):
        from . import restitution
        tenant = db.scalars(select(Tenant).where(Tenant.key == args.client.upper())).first()
        if tenant is None:
            print(f"Client inconnu : {args.client}", file=sys.stderr)
            return 1
        if args.cmd == "export-client":
            content, digest = restitution.export_bytes(db, settings, tenant, actor)
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(content)
            db.commit()
            print(f"Export de {tenant.key} : {args.out} ({len(content)} octets, SHA-256 {digest})")
            return 0
        execute = args.confirm == tenant.key
        try:
            comptes = restitution.destroy_client(db, settings, tenant, actor, dry_run=not execute)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        if execute:
            db.commit()
        for k, v in comptes.items():
            print(f"{k} : {v}")
        print("Données détruites." if execute else f"Simulation : relancer avec --confirm {tenant.key} pour détruire.")
        return 0
    if args.cmd == "purge":
        from . import retention
        from .ids import utcnow
        report = retention.run(db, settings, utcnow(), actor=actor, dry_run=not args.apply)
        if args.apply:
            db.commit()
        for r in report:
            if r.get("conserve"):
                print(f"{r['client']} : contexte conservé toute la prestation (PDIS IV.5.3.6), aucune purge")
                continue
            print(f"{r['client']} : {r['alerts']} alerte(s) brute(s) antérieure(s) au {r['before']} ({r['months']} mois)"
                  + ("" if args.apply else " [simulation]"))
        return 0

    if args.cmd == "import-mitre":
        import json
        from . import mitre_stix
        with open(args.file, encoding="utf-8") as f:
            added, updated = mitre_stix.import_bundle(db, json.load(f))
        audit.record(db, actor, "mitre.import", None, None, None, {"ajoutees": added, "mises_a_jour": updated})
        db.commit()
        print(f"{added} technique(s) ajoutée(s), {updated} mise(s) à jour.")
        return 0

    if args.cmd == "checkpoint":
        seq, seal = audit.head(db)
        print(f"{seq}:{seal}")
        return 0

    if args.cmd == "verify-audit":
        cp = None
        if args.checkpoint:
            seq, _, seal = args.checkpoint.partition(":")
            cp = (int(seq), seal)
        ok, bad = audit.verify_chain(db, cp)
        print("Chaîne d'audit intègre." if ok else f"Chaîne d'audit ROMPUE à l'entrée {bad}.")
        return 0 if ok else 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
