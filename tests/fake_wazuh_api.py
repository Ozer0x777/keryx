"""Faux manager Wazuh (API REST, port 55000 en vrai), pour les tests du parc d'agents (ADR-0030). Aucun service externe.

HTTPS local (même fabrique de certificats que le faux indexeur), POST /security/user/authenticate en Basic qui rend
un jeton, GET / (version de l'API) et GET /agents (pages, filtre de groupe) avec le jeton. Ce n'est PAS un Wazuh : il
vérifie le contrat que Keryx émet et sa tenue face à un serveur défaillant ou malveillant, pas la compatibilité avec
un vrai manager (noms de champs, permissions : à valider).
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import os
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .fake_indexer import make_pki

USER, PASSWORD, TOKEN = "keryx-api", "S3cret-api-de-test!", "jeton-de-test-0123456789"
NOW = dt.datetime.now(dt.timezone.utc)


def iso(when: dt.datetime) -> str:
    return when.replace(microsecond=0).isoformat()


def sample_agents() -> list[dict]:
    """Le manager (000, à ignorer), des agents des groupes « acme » et « delta », dans tous les états."""
    def ag(i, name, status, version, group, keep_h=0.0, add_d=30, osn="Ubuntu", osv="24.04"):
        a = {"id": i, "name": name, "ip": f"10.20.0.{int(i)}", "status": status, "group": ["default", group],
             "node_name": "worker-01", "dateAdd": iso(NOW - dt.timedelta(days=add_d)),
             "os": {"name": osn, "version": osv}}
        if version:
            a["version"] = f"Wazuh v{version}"
        if status != "never_connected":
            a["lastKeepAlive"] = iso(NOW - dt.timedelta(hours=keep_h))
        return a
    return [
        {"id": "000", "name": "wazuh-manager-01", "status": "active", "version": "Wazuh v4.12.0", "group": []},
        ag("001", "srv-ad-01", "active", "4.12.0", "acme", 0.001, osn="Microsoft Windows Server 2022", osv="10.0.20348"),
        ag("002", "srv-web-02", "disconnected", "4.9.2", "acme", 50),
        ag("003", "srv-web-01", "active", "4.11.2", "acme", 0.001),
        ag("004", "pc-rh-03", "disconnected", "4.12.0", "acme", 2),
        ag("005", "pc-dev-12", "never_connected", None, "acme", add_d=6),
        ag("006", "pc-stagiaire-02", "pending", "4.12.0", "acme", 0.01, add_d=0),
        ag("007", "srv-delta-01", "active", "4.12.0", "delta", 0.001),
    ]


class FakeWazuhApi:
    """Modes : ok | 500 | junk | redirect | leak (ignore le filtre de groupe) | no_token. `requests` garde chaque requête."""

    def __init__(self, directory: str, port: int = 0, agents: list[dict] | None = None, reuse_pki: bool = False):
        self.dir = str(directory)
        # reuse_pki : mêmes autorité et certificat qu'un faux indexeur déjà créé dans ce dossier (une autorité par client).
        self.ca_pem = open(os.path.join(self.dir, "ca.pem")).read() if reuse_pki else make_pki(self.dir)
        self.agents = sample_agents() if agents is None else agents
        self.mode, self.requests, self.version, self.page_max = "ok", [], "4.12.0", 500
        self.close_after_reply = False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status: int, obj, headers: dict | None = None):
                body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if outer.close_after_reply:
                    self.send_header("Connection", "close")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.do_POST()

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers)})
                if outer.mode == "redirect":
                    return self._send(302, b"", {"Location": "https://127.0.0.1:1/"})
                url = urlsplit(self.path)
                if url.path == "/security/user/authenticate":
                    expected = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
                    if self.headers.get("Authorization") != expected:
                        return self._send(401, {"title": "Unauthorized", "error": 401})
                    if outer.mode == "no_token":
                        return self._send(200, {"data": {}, "error": 0})
                    return self._send(200, {"data": {"token": TOKEN}, "error": 0})
                if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    return self._send(401, {"title": "Unauthorized", "error": 401})
                if outer.mode == "500":
                    return self._send(500, {"title": "Internal error DETAIL-INTERNE", "error": 500})
                if outer.mode == "junk":
                    return self._send(200, b"pas du JSON")
                if url.path == "/":
                    return self._send(200, {"data": {"title": "Wazuh API REST", "api_version": outer.version}, "error": 0})
                if url.path == "/agents":
                    q = {k: v[0] for k, v in parse_qs(url.query).items()}
                    # Comme le vrai manager (Wazuh 4.14) : un « + » non encodé se lit comme un espace, tri refusé.
                    if "sort" in q and q["sort"].lstrip("+-") not in ("id", "name", "dateAdd", "lastKeepAlive"):
                        return self._send(400, {"title": "Bad Request", "detail": f"Not a valid sort field: {q['sort']!r}",
                                                "error": 400})
                    items = list(outer.agents)
                    if q.get("group") and outer.mode != "leak":
                        items = [a for a in items if q["group"] in (a.get("group") or [])]
                    off, lim = int(q.get("offset", 0)), min(int(q.get("limit", 500)), outer.page_max)
                    return self._send(200, {"data": {"affected_items": items[off:off + lim], "total_affected_items": len(items),
                                                     "total_failed_items": 0, "failed_items": []}, "error": 0})
                return self._send(404, {"title": "Not found", "error": 404})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.httpd.daemon_threads = True
        self.httpd.handle_error = lambda *a: None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(self.dir, "server.pem"), os.path.join(self.dir, "server.key"))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.httpd.server_port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "FakeWazuhApi":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
