"""Faux indexeur compatible OpenSearch, pour les tests du contexte Wazuh (ADR-0021). Aucun service externe.

Serveur HTTPS local (autorité et certificat générés ici), authentification Basic, et le sous-ensemble de l'API
`_search` que Keryx émet : `bool.filter` avec `term` sur `agent.id` et `range` sur le champ de date, `sort`, `size`,
`_source`. Ce n'est PAS un Wazuh : il vérifie le contrat que Keryx émet et sa tenue face à un serveur défaillant ou
malveillant, pas la compatibilité avec un indexeur réel (noms de champs, motif d'index, certificats : à valider).

Utilisable seul, pour le banc de parcours (e2e) :
    python tests/fake_indexer.py DOSSIER PORT [identifiant de l'alerte]
écrit DOSSIER/ca.pem puis sert jusqu'à l'arrêt du processus.
"""
from __future__ import annotations

import base64
import datetime as dt
import fnmatch
import ipaddress
import json
import os
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

USER, PASSWORD = "keryx-lecture", "S3cret-indexeur-de-test!"
ALERT_ID = "1732113662.4417203"                      # identifiant de ALERT_SSH_BRUTEFORCE (tests/conftest.py)
ALERT_AT = dt.datetime(2026, 11, 20, 14, 41, 2, 118000, tzinfo=dt.timezone.utc)
INDEX = "wazuh-alerts-4.x-2026.11.20"
HOSTILE_LOG = "GET /?q=<script>alert(1)</script> \x1b[31mrouge\x00 ‮gnp.exe HTTP/1.1"


def make_pki(directory: str) -> str:
    """Autorité racine + certificat serveur pour 127.0.0.1 et localhost. Renvoie le PEM de l'autorité."""
    now = dt.datetime.now(dt.timezone.utc)

    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("Autorité de test du faux indexeur")).issuer_name(name("Autorité de test du faux indexeur"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name("faux-indexeur")).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                                        x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
    with open(os.path.join(directory, "ca.pem"), "w") as f:
        f.write(ca_pem)
    with open(os.path.join(directory, "server.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(os.path.join(directory, "server.key"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return ca_pem


def wazuh_time(when: dt.datetime) -> str:
    """Format des dates de Wazuh : 2026-11-20T14:41:02.118+0000."""
    return when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}+0000"


def parse_time(value: str) -> dt.datetime:
    if value.startswith("now-") and value.endswith("d"):       # date relative émise par le parc d'agents (ADR-0030)
        return dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=int(value[4:-1]))
    v = value[:-1] + "+00:00" if value.endswith("Z") else value
    if len(v) > 5 and v[-5] in "+-" and v[-4:].isdigit():
        v = v[:-2] + ":" + v[-2:]
    return dt.datetime.fromisoformat(v)


def sample_docs(alert_id: str = ALERT_ID, alert_at: dt.datetime = ALERT_AT) -> list[dict]:
    """Vingt événements avant et vingt après l'alerte pour l'agent 003, autant pour l'agent 004 aux mêmes instants
    (ils ne doivent jamais sortir), l'alerte elle-même, et un événement hostile juste après elle."""
    docs = []

    def add(agent: str, name: str, offset_s: int, n: int, log: str, doc_id: str | None = None):
        when = alert_at + dt.timedelta(seconds=offset_s)
        docs.append({"_index": INDEX, "_id": f"doc-{agent}-{n}", "_source": {
            "timestamp": wazuh_time(when), "@timestamp": when.isoformat().replace("+00:00", "Z"),
            "id": doc_id or f"{int(when.timestamp())}.{agent}{n:04d}",
            "rule": {"id": "5710" if offset_s else "5712", "level": 5 if offset_s else 10,
                     "description": f"sshd: événement {n} de {name}", "groups": ["sshd"]},
            "agent": {"id": agent, "name": name, "ip": "10.20.1.15"}, "manager": {"name": "wazuh-manager-01"},
            "decoder": {"name": "sshd"}, "location": "/var/log/auth.log", "full_log": log,
            "data": {"srcip": "185.220.101.4", "srcuser": "root"},
        }})

    for i in range(1, 21):
        add("003", "srv-web-01", -10 * i, 100 - i, f"sshd[2211]: avant {i} srv-web-01")
        add("003", "srv-web-01", 10 * i, 100 + i, HOSTILE_LOG if i == 1 else f"sshd[2211]: après {i} srv-web-01")
        add("004", "pc-rh-03", -10 * i + 1, 200 - i, f"SECRET-AUTRE-AGENT avant {i}")
        add("004", "pc-rh-03", 10 * i - 1, 200 + i, f"SECRET-AUTRE-AGENT après {i}")
    add("003", "srv-web-01", 0, 100, "sshd[2211]: Failed password for root from 185.220.101.4 port 51344 ssh2", alert_id)
    return docs


def _get(source: dict, path: str):
    cur = source
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _project(source: dict, includes: list[str] | None) -> dict:
    if not includes:
        return source
    out: dict = {}
    for path in includes:
        value = _get(source, path)
        if value is None:
            continue
        cur = out
        parts = path.split(".")
        for part in parts[:-1]:
            cur = cur.setdefault(part, {})
        cur[parts[-1]] = value
    return out


def search(docs: list[dict], index_pattern: str, body: dict, ignore_agent: bool = False) -> dict:
    """Évalue le sous-ensemble de requête que Keryx émet. Une requête hors de ce sous-ensemble lève ValueError (400)."""
    filters = body["query"]["bool"]["filter"]
    hits = [d for d in docs if fnmatch.fnmatchcase(d["_index"], index_pattern)]
    field = None
    for f in filters:
        if "term" in f:
            (path, wanted), = f["term"].items()
            if not (ignore_agent and path == "agent.id"):
                hits = [d for d in hits if _get(d["_source"], path) == wanted]
        elif "terms" in f:
            (path, wanted), = f["terms"].items()
            if not (ignore_agent and path == "agent.id"):
                hits = [d for d in hits if _get(d["_source"], path) in wanted]
        elif "range" in f:
            (field, bounds), = f["range"].items()
            for op, value in bounds.items():
                if op == "format":
                    continue
                pivot = parse_time(value)
                keep = {"lt": lambda t: t < pivot, "lte": lambda t: t <= pivot, "gt": lambda t: t > pivot, "gte": lambda t: t >= pivot}[op]
                hits = [d for d in hits if keep(parse_time(_get(d["_source"], field)))]
        else:
            raise ValueError("filtre non pris en charge par le faux indexeur")
    if "aggs" in body:
        # Agrégation « dernier événement par agent » du parc d'agents : terms sur agent.id, max sur le champ de date.
        spec = body["aggs"]["agents"]
        tfield, mfield = spec["terms"]["field"], spec["aggs"]["last"]["max"]["field"]
        last: dict = {}
        for d in hits:
            key, when = _get(d["_source"], tfield), parse_time(_get(d["_source"], mfield))
            if key is not None and (key not in last or when > last[key]):
                last[key] = when
        buckets = [{"key": k, "doc_count": 1, "last": {"value": v.timestamp() * 1000,
                    "value_as_string": v.isoformat().replace("+00:00", "Z")}} for k, v in sorted(last.items())]
        return {"took": 1, "timed_out": False, "hits": {"hits": []},
                "aggregations": {"agents": {"buckets": buckets[: int(spec["terms"].get("size", 10))]}}}
    (sort_field, sort_spec), = body["sort"][0].items()
    hits.sort(key=lambda d: parse_time(_get(d["_source"], sort_field)), reverse=sort_spec["order"] == "desc")
    hits = hits[: int(body.get("size", 10))]
    return {"took": 1, "timed_out": False, "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"max_score": None, "hits": [
                {"_index": d["_index"], "_id": d["_id"], "_score": None, "_source": _project(d["_source"], body.get("_source")),
                 "sort": [int(parse_time(_get(d["_source"], sort_field)).timestamp() * 1000)]} for d in hits]}}


class FakeIndexer:
    """Modes : ok | 500 | junk | huge | slow | redirect | leak (ignore le filtre d'agent) | bad_shape (JSON sans résultats de recherche).
    `requests` garde chaque requête reçue (chemin, en-têtes, corps) pour les assertions."""

    def __init__(self, directory: str, port: int = 0, docs: list[dict] | None = None):
        self.dir = str(directory)
        self.ca_pem = make_pki(self.dir)
        self.docs = sample_docs() if docs is None else docs
        self.mode, self.requests, self.redirect_to, self.delay = "ok", [], None, 0.0
        self.close_after_reply = False      # « Connection: close » après chaque réponse (mandataire, ancien serveur)
        self.user, self.password = USER, PASSWORD
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status: int, body: bytes, ctype: str = "application/json; charset=UTF-8", headers: dict | None = None):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
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
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append({"method": self.command, "path": self.path, "headers": dict(self.headers), "body": raw})
                if outer.delay:
                    time.sleep(outer.delay)
                if outer.mode == "redirect":
                    return self._send(302, b"", headers={"Location": outer.redirect_to or "https://127.0.0.1:1/"})
                expected = "Basic " + base64.b64encode(f"{outer.user}:{outer.password}".encode()).decode()
                if self.headers.get("Authorization") != expected:
                    return self._send(401, b'{"error":"Unauthorized"}', headers={"WWW-Authenticate": 'Basic realm="OpenSearch Security"'})
                if outer.mode == "500":
                    return self._send(500, json.dumps({"error": {"type": "exception", "reason": "panne interne DETAIL-INTERNE"}}).encode())
                if outer.mode == "junk":
                    return self._send(200, b"pas du JSON")
                if outer.mode == "bad_shape":
                    return self._send(200, b'{"hits": "non"}')
                if outer.mode == "huge":
                    return self._send(200, b'{"hits":{"hits":[]},"pad":"' + b"x" * (3 * 1024 * 1024) + b'"}')
                path, _, _query = self.path.partition("?")
                parts = [p for p in path.split("/") if p]
                if self.command != "POST" or len(parts) < 2 or parts[-1] != "_search":
                    return self._send(404, b'{"error":"no handler"}')
                try:
                    out = search(outer.docs, parts[-2], json.loads(raw), ignore_agent=outer.mode == "leak")
                except (KeyError, ValueError, TypeError) as exc:
                    return self._send(400, json.dumps({"error": {"type": "parsing_exception", "reason": str(exc)}}).encode())
                self._send(200, json.dumps(out).encode())

        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.httpd.daemon_threads = True
        self.httpd.handle_error = lambda *a: None       # client parti avant la réponse (essais de délai) : pas de trace
        self.stopped = False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(self.dir, "server.pem"), os.path.join(self.dir, "server.key"))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_port
        self.url = f"https://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self) -> "FakeIndexer":
        self.thread.start()
        return self

    def searches(self) -> list[dict]:
        return [json.loads(r["body"]) for r in self.requests if r["path"].split("?")[0].endswith("/_search")]

    def stop(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        if self.thread.is_alive():
            self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":
    directory, port = sys.argv[1], int(sys.argv[2])
    alert_id = sys.argv[3] if len(sys.argv) > 3 else ALERT_ID
    os.makedirs(directory, exist_ok=True)
    fake = FakeIndexer(directory, port, sample_docs(alert_id))
    print(json.dumps({"url": fake.url, "ca": os.path.join(directory, "ca.pem"), "user": USER, "password": PASSWORD}), flush=True)
    fake.httpd.serve_forever()
