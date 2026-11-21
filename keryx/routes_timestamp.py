"""Horodatage de confiance (RFC 3161) des pièces et des points de contrôle d'audit.

[RFC 3161 ; ISO/IEC 27037 ; PRIS VI.5.3.c ; ISO/IEC 27002 8.15] Désactivé tant que KERYX_TSA_URL n'est pas défini.
Les droits sont ceux de la pièce : un jeton n'est lisible que par qui peut lire la pièce ; ceux du journal d'audit,
par l'Admin seulement.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from . import audit, timestamping as ts
from .ids import rfc3339
from .models import CustodyEvent, Timestamp, User


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit, settings = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit, ctx.settings

    def enabled() -> None:
        if not settings.tsa_url:
            raise HTTPException(409, "L'horodatage de confiance n'est pas configuré (KERYX_TSA_URL).")

    def view(t: Timestamp) -> dict:
        return {"id": t.id, "object_type": t.object_type, "object_id": t.object_id, "gen_time": rfc3339(t.gen_time),
                "serial": t.serial, "tsa_url": t.tsa_url, "created_by": t.created_by}

    def issue(db: DbSession, user: User, object_type: str, object_id: str, digest: str, tenant_id: str | None) -> Timestamp:
        message = ts.message_for(object_type, object_id, digest)
        try:
            r = ts.stamp(settings.tsa_url, message, settings.tsa_ca_file, http=ts.make_client(settings),
                         policy_oid=settings.tsa_policy_oid)
        except ts.TimestampError as exc:
            raise HTTPException(502, str(exc))
        row = Timestamp(object_type=object_type, object_id=object_id, tenant_id=tenant_id, message=message.decode(),
                        token=r["token"], gen_time=r["gen_time"], serial=r["serial"], tsa_url=settings.tsa_url,
                        created_by=user.username)
        db.add(row)
        db.flush()
        return row

    @app.post("/api/v1/attachments/{attachment_id}/timestamp", status_code=201)
    def stamp_attachment(attachment_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        enabled()
        a, t = ctx.load_attachment(db, user, attachment_id)
        row = issue(db, user, "attachment", a.id, a.sha256, a.tenant_id)
        db.add(CustodyEvent(attachment_id=a.id, actor=user.username, action="horodatage", reason=f"RFC 3161 · série {row.serial}"))
        ctx.event(db, t, user, "horodatage", {"piece": a.id, "sha256": a.sha256, "heure_attestee": rfc3339(row.gen_time)})
        commit(db)
        return view(row)

    @app.get("/api/v1/attachments/{attachment_id}/timestamps")
    def list_attachment(attachment_id: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        a, _t = ctx.load_attachment(db, user, attachment_id)
        rows = db.scalars(select(Timestamp).where(Timestamp.object_type == "attachment", Timestamp.object_id == a.id)
                          .order_by(Timestamp.gen_time)).all()
        return {"enabled": bool(settings.tsa_url), "items": [view(r) for r in rows]}

    def readable(db: DbSession, user: User, tid: str) -> Timestamp:
        row = db.get(Timestamp, tid[:36])
        if row is None:
            raise HTTPException(404, "Jeton introuvable.")
        if row.object_type == "audit":
            require_role(user, "admin")
        elif row.object_type == "attachment":
            # Les droits sont ceux de la pièce (client du même client : pièces visibles seulement ; Admin : aucune).
            try:
                ctx.load_attachment(db, user, row.object_id)
            except HTTPException:
                raise HTTPException(404, "Jeton introuvable.") from None
        elif row.tenant_id not in ctx.visible_tenant_ids(user):
            raise HTTPException(404, "Jeton introuvable.")
        return row

    @app.get("/api/v1/timestamps/{tid}/token")
    def download(tid: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        row = readable(db, user, tid)
        return Response(row.token, media_type="application/timestamp-reply",
                        headers={"Content-Disposition": f'attachment; filename="keryx-{row.object_type}-{row.serial}.tsr"',
                                 "Cache-Control": "no-store"})

    @app.post("/api/v1/timestamps/{tid}/verify")
    def verify(tid: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        """Revérifie le jeton conservé : signature, chaîne jusqu'aux certificats configurés, message."""
        row = readable(db, user, tid)
        try:
            when = ts.verify(row.token, row.message.encode(), settings.tsa_ca_file, settings.tsa_policy_oid)
        except ts.TimestampError as exc:
            return {"valid": False, "error": str(exc)}
        return {"valid": True, "gen_time": rfc3339(when)}

    # ---------------------------------------------------------------- point de contrôle du journal d'audit
    @app.post("/api/v1/audit/checkpoint/timestamp", status_code=201)
    def stamp_checkpoint(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        enabled()
        seq, seal = audit.head(db)
        if seq == 0:
            raise HTTPException(409, "Le journal d'audit est vide.")
        row = issue(db, user, "audit", str(seq), seal, None)
        audit.record(db, user.username, "audit.checkpoint_timestamped", None, None, None, {"seq": seq, "serial": row.serial})
        commit(db)
        return {**view(row), "seq": seq, "seal": seal}

    @app.get("/api/v1/audit/timestamps")
    def list_checkpoints(user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "admin")
        rows = db.scalars(select(Timestamp).where(Timestamp.object_type == "audit").order_by(Timestamp.gen_time.desc()).limit(50)).all()
        return {"enabled": bool(settings.tsa_url), "items": [{**view(r), "seq": int(r.object_id), "seal": r.message.rsplit(":", 1)[-1]} for r in rows]}
