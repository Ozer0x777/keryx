"""Faux VirusTotal local, pour les tests de la recherche d'empreinte (ADR-0022). Aucun service externe.

Serveur HTTP sur la boucle locale qui imite le seul appel que Keryx émet : `GET /api/v3/files/{empreinte}` avec
l'en-tête `x-apikey`. Ce n'est PAS VirusTotal : il vérifie le contrat que Keryx émet et sa tenue face à un serveur
défaillant ou malveillant, pas la compatibilité avec le service réel (forme exacte des réponses, des erreurs et des
clés : à valider, voir ADR-0022).

Utilisable seul, pour le banc de parcours (e2e) :
    python tests/fake_virustotal.py PORT
affiche l'adresse, la clé attendue et les empreintes connues, puis sert jusqu'à l'arrêt du processus.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"     # fausse clé, 64 caractères
EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = hashlib.sha256(EICAR).hexdigest()
EICAR_SHA1 = hashlib.sha1(EICAR).hexdigest()
EMPTY_ZIP = bytes.fromhex("504b0506" + "00" * 18)        # archive ZIP vide : la pièce déposée par le parcours e2e
EMPTY_ZIP_SHA256 = hashlib.sha256(EMPTY_ZIP).hexdigest()
QUIET_SHA256 = "c0ffee" + "0" * 58                        # connu, aucune détection
HOSTILE_SHA256 = "bad0" * 16                              # connu, textes hostiles
UNKNOWN_SHA256 = "f" * 64
HOSTILE_NAME = "facture<script>alert(1)</script>\x1b[31m\x00‮gpj.exe"
HOSTILE_LABEL = "<img src=x onerror=alert(1)>trojan.‮evil/" + "A" * 400


def attributes(sha256: str, sha1: str | None = None, malicious: int = 0, name: str = "fichier.bin", **extra) -> dict:
    results = {f"Moteur{i:02d}": {"category": "malicious", "engine_name": f"Moteur{i:02d}", "result": f"Trojan.Generic.{i}"}
               for i in range(malicious)}
    results.update({f"Calme{i:02d}": {"category": "undetected", "engine_name": f"Calme{i:02d}", "result": None}
                    for i in range(70 - malicious)})
    out = {
        "sha256": sha256, "sha1": sha1 or hashlib.sha1(sha256.encode()).hexdigest(), "md5": "0" * 32,
        "meaningful_name": name, "type_description": "Win32 EXE", "size": 68,
        "last_analysis_date": 1794650400, "first_submission_date": 1148301722,       # 2026-11-14 10:00:00Z ; 2006-05-22
        "last_analysis_stats": {"malicious": malicious, "suspicious": 1 if malicious else 0, "harmless": 0,
                                "undetected": 70 - malicious, "timeout": 0, "failure": 0, "type-unsupported": 2},
        "last_analysis_results": results,
        "popular_threat_classification": {"suggested_threat_label": "trojan.eicar/test" if malicious else ""},
        "links": {"self": "https://attaquant.example/voler"},     # jamais repris par Keryx
    }
    out.update(extra)
    return out


def sample_files() -> dict[str, dict]:
    eicar = attributes(EICAR_SHA256, EICAR_SHA1, malicious=62, name="eicar.com")
    hostile = attributes(HOSTILE_SHA256, malicious=3, name=HOSTILE_NAME, type_description="<b>PE</b>\x07",
                         popular_threat_classification={"suggested_threat_label": HOSTILE_LABEL})
    hostile["last_analysis_results"]["<script>x</script>"] = {"category": "malicious", "result": "Evil\r\n‮<svg onload=1>"}
    hostile["last_analysis_stats"]["malicious"] = "beaucoup"                       # type inattendu : compté 0
    hostile["last_analysis_date"] = "hier"
    return {
        EICAR_SHA256: eicar, EICAR_SHA1: eicar,
        EMPTY_ZIP_SHA256: attributes(EMPTY_ZIP_SHA256, malicious=12, name="preuve.zip", type_description="ZIP"),
        QUIET_SHA256: attributes(QUIET_SHA256, name="outil-interne.exe"),
        HOSTILE_SHA256: hostile,
    }


class FakeVirusTotal:
    """Modes : ok | 401 | 403 | 429 | 500 | junk | bad_shape | huge | slow | redirect | gzip | gzip_bomb | html404 |
    other_file (renvoie le rapport d'un autre fichier). `requests` garde chaque requête reçue pour les assertions."""

    def __init__(self, port: int = 0, files: dict[str, dict] | None = None, tls_dir: str | None = None):
        self.files = sample_files() if files is None else files
        self.mode, self.requests, self.delay, self.key = "ok", [], 0.0, API_KEY
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status: int, body: bytes, ctype: str = "application/json", headers: dict | None = None):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:      # le client a coupé (réponse trop grande, délai) : rien à faire
                    pass

            def _error(self, status: int, code: str, message: str):
                self._send(status, json.dumps({"error": {"code": code, "message": message}}).encode())

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append({"method": "POST", "path": self.path, "headers": dict(self.headers)})
                self._error(405, "NotAllowedError", "le faux serveur ne reçoit aucun fichier")

            do_PUT = do_PATCH = do_DELETE = do_POST

            def do_GET(self):
                outer.requests.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
                if outer.delay:
                    time.sleep(outer.delay)
                mode = outer.mode
                if mode == "redirect":
                    return self._send(302, b"", headers={"Location": f"http://127.0.0.1:{outer.port}/api/v3/files/{EICAR_SHA256}"})
                if mode == "html404":
                    return self._send(404, b"<html><body>404 Not Found</body></html>", "text/html")
                if mode == "401" or self.headers.get("x-apikey") != outer.key:
                    return self._error(401, "WrongCredentialsError", "Wrong API key")
                if mode == "403":
                    return self._error(403, "ForbiddenError", "You are not allowed to perform the requested operation")
                if mode == "429":
                    return self._error(429, "QuotaExceededError", "Quota exceeded DETAIL-INTERNE")
                if mode == "500":
                    return self._error(500, "TransientError", "panne interne DETAIL-INTERNE")
                if mode == "junk":
                    return self._send(200, b"pas du JSON")
                if mode == "bad_shape":
                    return self._send(200, b'{"data": "non"}')
                if mode == "huge":
                    return self._send(200, b'{"data":{"attributes":{}},"pad":"' + b"x" * (5 * 1024 * 1024) + b'"}')
                if mode == "gzip_bomb":
                    return self._send(200, gzip.compress(b'{"pad":"' + b"x" * (64 * 1024 * 1024) + b'"}'), headers={"Content-Encoding": "gzip"})
                path = self.path.split("?")[0]
                if path.startswith("http://"):       # requête en forme absolue : le faux serveur joue le mandataire
                    path = "/" + path.split("/", 3)[3]
                parts = path.split("/")
                if len(parts) != 5 or parts[:4] != ["", "api", "v3", "files"]:
                    return self._error(404, "NotFoundError", "no handler")
                found = outer.files.get(parts[4])
                if mode == "other_file":
                    found = outer.files[EICAR_SHA256]
                if found is None:
                    return self._error(404, "NotFoundError", f'File "{parts[4]}" not found')
                body = json.dumps({"data": {"type": "file", "id": found["sha256"], "attributes": found,
                                            "links": {"self": "https://attaquant.example/voler"}}}).encode()
                if mode == "gzip":
                    return self._send(200, gzip.compress(body), headers={"Content-Encoding": "gzip"})
                self._send(200, body)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.httpd.daemon_threads = True
        self.httpd.handle_error = lambda *a: None
        self.stopped = False
        self.port = self.httpd.server_port
        self.url = f"http://127.0.0.1:{self.port}"
        self.ca_pem = None
        if tls_dir:      # HTTPS avec une autorité privée (celle du faux indexeur) : inconnue du système
            import os
            import ssl

            from .fake_indexer import make_pki
            self.ca_pem = make_pki(str(tls_dir))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(os.path.join(str(tls_dir), "server.pem"), os.path.join(str(tls_dir), "server.key"))
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            self.url = f"https://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "FakeVirusTotal":
        self.thread.start()
        return self

    def stop(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        if self.thread.is_alive():
            self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    fake = FakeVirusTotal(int(sys.argv[1]))
    print(json.dumps({"url": fake.url, "key": API_KEY, "eicar": EICAR_SHA256, "piece": EMPTY_ZIP_SHA256,
                      "quiet": QUIET_SHA256, "unknown": UNKNOWN_SHA256}), flush=True)
    fake.httpd.serve_forever()
