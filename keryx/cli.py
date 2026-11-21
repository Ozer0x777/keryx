"""Administration en ligne de commande (actions tracées dans le journal d'audit).

Exemples :
  python -m keryx.cli init-db
  python -m keryx.cli add-client ACME "ACME Industrie"
  python -m keryx.cli add-user sbenali "S. Benali" analyst --clients ACME
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
    k = sub.add_parser("add-api-key"); k.add_argument("client_key"); k.add_argument("name")
    m = sub.add_parser("add-mitre")
    g = m.add_mutually_exclusive_group(required=True)
    g.add_argument("--rule"); g.add_argument("--group")
    m.add_argument("technique"); m.add_argument("name", nargs="?", default=""); m.add_argument("tactic", nargs="?", default="")
    va = sub.add_parser("verify-audit"); va.add_argument("--checkpoint")
    sub.add_parser("checkpoint")
    sc = sub.add_parser("set-contacts"); sc.add_argument("client_key"); sc.add_argument("emails", nargs="*")
    sub.add_parser("gen-key")
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
        password = os.environ.get("KERYX_NEW_PASSWORD") or getpass.getpass("Mot de passe (12 caractères min.) : ")
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
            quarantined = a.scan_status == "quarantaine"
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

    if args.cmd == "purge":
        from . import retention
        from .ids import utcnow
        report = retention.run(db, settings, utcnow(), actor=actor, dry_run=not args.apply)
        if args.apply:
            db.commit()
        for r in report:
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
