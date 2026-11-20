#!/var/ossec/framework/python/bin/python3
"""Intégration Wazuh → Keryx.

Wazuh appelle ce script pour chaque alerte correspondant au bloc <integration> :
  argv[1] = chemin du fichier JSON de l'alerte
  argv[2] = api_key (clé d'ingestion Keryx)
  argv[3] = hook_url (ex. https://keryx.example.eu/api/v1/ingest/wazuh)

- Bibliothèque standard uniquement : rien à installer sur le manager.
- HTTPS obligatoire, certificat vérifié (KERYX_CA_BUNDLE pour une AC interne), redirections refusées
  (la clé ne doit jamais partir vers un autre serveur).
- Si Keryx est injoignable, l'alerte est mise en file d'attente sur disque et renvoyée aux
  appels suivants : aucune alerte perdue tant que le disque n'est pas plein (plafond configurable).
- Keryx dédoublonne sur l'identifiant d'alerte Wazuh : un renvoi n'est jamais compté deux fois.
"""
import fcntl
import glob
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

LOG_FILE = "/var/ossec/logs/integrations.log"
SPOOL_DIR = os.environ.get("KERYX_SPOOL_DIR", "/var/ossec/var/keryx-spool")
SPOOL_MAX_FILES = int(os.environ.get("KERYX_SPOOL_MAX", "50000"))
FLUSH_PER_RUN = 20
TIMEOUT_S = 8
DEFINITIVE = (400, 401, 403, 413, 422)  # erreurs définitives : renvoyer ne servirait à rien


def log(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).isoformat()} custom-keryx: {msg}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        sys.stderr.write(line)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirection refusée", headers, fp)


def _opener() -> urllib.request.OpenerDirector:
    ctx = ssl.create_default_context(cafile=os.environ.get("KERYX_CA_BUNDLE") or None)
    return urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))


def post(opener, hook_url: str, api_key: str, body: bytes) -> str:
    """Renvoie 'ok', 'definitif' (ne pas renvoyer) ou 'reessayer'."""
    req = urllib.request.Request(
        hook_url, data=body, method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}",
                 "User-Agent": "wazuh-custom-keryx/0.2"},
    )
    try:
        with opener.open(req, timeout=TIMEOUT_S) as resp:
            raw = resp.read(65536)
            try:
                result = json.loads(raw or b"{}")
            except ValueError:
                result = {}
            log(f"→ HTTP {resp.status} {result.get('status', '?')} {result.get('ticket', '')}")
            return "ok"
    except urllib.error.HTTPError as exc:
        log(f"HTTP {exc.code}")
        return "definitif" if exc.code in DEFINITIVE else "reessayer"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        log(f"erreur réseau : {type(exc).__name__}")
        return "reessayer"


def spool(body: bytes) -> None:
    os.makedirs(SPOOL_DIR, mode=0o700, exist_ok=True)
    if len(os.listdir(SPOOL_DIR)) >= SPOOL_MAX_FILES:
        log("file d'attente pleine : alerte non conservée (voir KERYX_SPOOL_MAX)")
        return
    name = os.path.join(SPOOL_DIR, f"{time.time_ns()}-{uuid.uuid4().hex}.json")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(body)
    log("alerte mise en file d'attente")


def flush_spool(opener, hook_url: str, api_key: str) -> None:
    if not os.path.isdir(SPOOL_DIR):
        return
    lock_path = os.path.join(SPOOL_DIR, ".lock")
    with open(lock_path, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)  # un seul vidage à la fois
        except OSError:
            return
        for path in sorted(glob.glob(os.path.join(SPOOL_DIR, "*.json")))[:FLUSH_PER_RUN]:
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except OSError:
                continue
            outcome = post(opener, hook_url, api_key, body)
            if outcome == "reessayer":
                return  # Keryx toujours indisponible : on garde la file en l'état
            os.remove(path)  # ok, ou erreur définitive (journalisée)


def main(argv: list) -> int:
    if len(argv) < 4:
        log("arguments manquants (fichier d'alerte, api_key, hook_url)")
        return 1
    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    if not hook_url.startswith("https://"):
        log("hook_url doit être en HTTPS")
        return 1
    try:
        with open(alert_file, encoding="utf-8") as f:
            body = json.dumps(json.load(f)).encode("utf-8")
    except (OSError, ValueError) as exc:
        log(f"lecture de l'alerte impossible : {type(exc).__name__}")
        return 1

    opener = _opener()
    outcome = post(opener, hook_url, api_key, body)
    if outcome == "reessayer":
        time.sleep(2)
        outcome = post(opener, hook_url, api_key, body)
    if outcome == "reessayer":
        spool(body)
        return 1
    flush_spool(opener, hook_url, api_key)  # Keryx répond : on renvoie la file d'attente
    return 0 if outcome == "ok" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
