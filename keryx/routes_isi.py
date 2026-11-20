"""Classification ETSI GS ISI 002 d'un ticket et export IODEF 2.0 recommandé par l'ETSI (voir isi.py).
[PDIS IV.2.1.y ; ETSI GS ISI 002 clause 4.4, Annexe B, clause 7.4 ; RFC 7970, 8727]"""
from __future__ import annotations

from fastapi import Depends, HTTPException
from sqlalchemy.orm import Session as DbSession

from . import audit, isi
from .iodef import validate
from .ids import utcnow
from .models import Tenant, User


def register(app, ctx) -> None:
    get_db, current_user, require_role, commit = ctx.get_db, ctx.current_user, ctx.require_role, ctx.commit

    @app.get("/api/v1/isi/dictionary")
    def dictionary(user: User = Depends(current_user)):
        require_role(user, "analyst", "manager")
        return {"categories": isi.CATEGORIES, "mandatory": list(isi.MANDATORY), "multi": isi.MULTI,
                "axes": {a: [{"code": c, "ref": r, "label": l} for c, (r, l) in vals.items()] for a, vals in isi.AXES.items()},
                "how": [{"code": c, "ref": r.replace("B.1.2.", "B.1.3."), "label": l} for c, (r, l) in isi.AXES["what"].items()]}

    @app.get("/api/v1/tickets/{ref}/isi")
    def get_isi(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = ctx.load_ticket(db, user, ref)
        return {"isi": t.isi or {}, "missing": isi.missing(t.isi)}

    @app.put("/api/v1/tickets/{ref}/isi")
    def put_isi(ref: str, body: dict, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = ctx.load_ticket(db, user, ref)
        ctx.require_open(t)
        try:
            new = isi.clean(body)
        except isi.IsiError as exc:
            raise HTTPException(422, str(exc))
        before = t.isi or {}
        t.isi, t.updated_at = new, utcnow()
        ctx.event(db, t, user, "classification_isi", {"avant": before, "apres": new})
        commit(db)
        return {"isi": new, "missing": isi.missing(new)}

    @app.get("/api/v1/tickets/{ref}/isi/iodef")
    def export_isi(ref: str, user: User = Depends(current_user), db: DbSession = Depends(get_db)):
        require_role(user, "analyst", "manager")
        t = ctx.load_ticket(db, user, ref)
        gaps = isi.missing(t.isi)
        if gaps:
            raise HTTPException(409, f"Classification ETSI ISI incomplète : renseigner {', '.join(gaps)} (axes obligatoires).")
        tenant = db.get(Tenant, t.tenant_id)
        doc = isi.to_iodef(t, tenant.name, t.isi, utcnow())
        problems = validate(doc)
        if problems:
            raise HTTPException(500, "Export ETSI ISI non conforme à la structure attendue.")
        audit.record(db, user.username, "ticket.export_isi", "ticket", t.ref, t.tenant_id)
        commit(db)
        return doc
