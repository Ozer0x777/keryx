"""Taille maximale du corps des requêtes, contrôlée AVANT l'application.

[ASVS 5.0 V4 (limites de taille des requêtes) ; ISO/IEC 27002:2022 8.6 capacité] FastAPI lit le corps entier (JSON en
mémoire, multipart sur disque) avant de vérifier la session : sans borne, un inconnu saturerait la mémoire ou le disque.
Ici, la borne s'applique dès les en-têtes (Content-Length) puis au fil de la lecture (envoi par morceaux). Les routes
qui acceptent un gros corps (dépôt d'une pièce, import du référentiel ATT&CK) ne l'acceptent que d'une session ouverte ;
sans session, elles gardent la borne ordinaire. L'ingestion Wazuh a sa propre borne, plus basse (max_alert_bytes).
"""
from __future__ import annotations

import json
import re
from http.cookies import SimpleCookie

from starlette.concurrency import run_in_threadpool


class BodyLimitMiddleware:
    def __init__(self, app, default_limit: int, large: list[tuple[re.Pattern, int]], cookie_name: str, has_session):
        self.app, self.default_limit, self.large = app, default_limit, large
        self.cookie_name, self.has_session = cookie_name, has_session

    async def _limit(self, scope, headers: dict[bytes, bytes]) -> int:
        for pattern, limit in self.large:
            if pattern.match(scope["path"]):
                try:
                    cookie = SimpleCookie(headers.get(b"cookie", b"").decode("latin-1"))
                    token = cookie[self.cookie_name].value if self.cookie_name in cookie else None
                except Exception:  # noqa: BLE001 - en-tête Cookie illisible : pas de session
                    token = None
                if token and len(token) <= 100 and await run_in_threadpool(self.has_session, token):
                    return limit
        return self.default_limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope["headers"])
        limit = await self._limit(scope, headers)
        state = {"received": 0, "rejected": False, "started": False}

        async def reject() -> None:
            state["rejected"] = True
            if state["started"]:
                return
            body = json.dumps({"type": "about:blank", "title": "Contenu trop volumineux", "status": 413,
                               "detail": "Le corps de la requête dépasse la taille admise."}).encode("utf-8")
            await send({"type": "http.response.start", "status": 413, "headers": [
                (b"content-type", b"application/problem+json"), (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"), (b"x-content-type-options", b"nosniff"), (b"connection", b"close")]})
            await send({"type": "http.response.body", "body": body})

        declared = headers.get(b"content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            return await reject()

        async def bounded_receive():
            if state["rejected"]:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                state["received"] += len(message.get("body", b""))
                if state["received"] > limit:
                    await reject()
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            if state["rejected"]:
                return          # la réponse 413 est déjà partie : ce que l'application tente ensuite est ignoré
            if message["type"] == "http.response.start":
                state["started"] = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, guarded_send)
        except Exception:
            if not state["rejected"]:
                raise
