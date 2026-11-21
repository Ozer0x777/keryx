"""Autorité d'horodatage RFC 3161 de test, fondée sur l'outil « openssl ts » (aucun service externe)."""
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

TSA_CNF = """
[tsa]
default_tsa = tsa1
[tsa1]
dir = {d}
serial = {d}/serial
crypto_device = builtin
signer_cert = {d}/tsa.pem
signer_key = {d}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 1.2.3.4.5
digests = sha256, sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""
EXT = "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\nsubjectKeyIdentifier=hash\n"


def have_openssl() -> bool:
    return shutil.which("openssl") is not None


def run(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def make_pki(d: str) -> str:
    """Crée une autorité racine et un certificat de TSA ; renvoie le chemin du PEM de la racine."""
    d = str(d)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
        "-subj", "/CN=Racine de test Keryx", "-days", "30", cwd=d)
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr", "-subj", "/CN=TSA de test Keryx", cwd=d)
    open(os.path.join(d, "ext.cnf"), "w").write(EXT)
    run("openssl", "x509", "-req", "-in", "tsa.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "tsa.pem",
        "-days", "30", "-extfile", "ext.cnf", cwd=d)
    open(os.path.join(d, "serial"), "w").write("01\n")
    open(os.path.join(d, "tsa.cnf"), "w").write(TSA_CNF.format(d=d))
    return os.path.join(d, "ca.pem")


class Tsa:
    """Serveur HTTP local qui répond aux demandes RFC 3161 avec « openssl ts -reply »."""

    def __init__(self, d: str):
        self.d, self.mode, self.calls, self.auth = str(d), "ok", 0, None   # auth : « identifiant:mot de passe » exigé en Basic
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                outer.calls += 1
                if outer.auth:
                    import base64
                    if self.headers.get("Authorization") != "Basic " + base64.b64encode(outer.auth.encode()).decode():
                        self.send_response(401); self.end_headers(); return
                body = self.rfile.read(int(self.headers["Content-Length"]))
                if outer.mode == "500":
                    self.send_response(500); self.end_headers(); return
                if outer.mode == "junk":
                    self.send_response(200); self.end_headers(); self.wfile.write(b"pas du DER"); return
                q = os.path.join(outer.d, "q.tsq")
                open(q, "wb").write(body)
                subprocess.run(["openssl", "ts", "-reply", "-config", "tsa.cnf", "-section", "tsa1", "-queryfile", "q.tsq",
                                "-out", "r.tsr"], cwd=outer.d, check=True, capture_output=True)
                data = open(os.path.join(outer.d, "r.tsr"), "rb").read()
                self.send_response(200); self.send_header("Content-Type", "application/timestamp-reply"); self.end_headers()
                self.wfile.write(data)

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/tsa"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        self.httpd.shutdown()
