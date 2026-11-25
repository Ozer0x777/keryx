#!/usr/bin/env python3
"""Contrôles du dépôt, lancés par la CI (et à lancer avant un push) : aucun secret suivi par git, aucun tiret
cadratin dans la documentation Markdown (règle de rédaction du projet).

Usage : python3 scripts/verif_depot.py   (code de sortie 1 au premier problème trouvé, liste complète affichée)
"""
import re
import subprocess
import sys

# Motifs de secrets. Les exemples de la documentation (kx_REMPLACER_PAR_LA_CLE…) ne ressemblent pas à une vraie clé.
SECRETS = [
    ("clé privée PEM", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED |DSA )?PRIVATE KEY-----")),
    ("clé d'ingestion Keryx", re.compile(r"\bkx_[A-Za-z0-9_-]{40,}\b")),
    ("clé d'accès AWS ou S3", re.compile(r"\b(?:AKIA|ASIA|GK)[0-9A-Z]{16,}\b")),
    ("jeton GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("clé secrète Keryx en clair", re.compile(r"^KERYX_SECRET_KEY=[A-Za-z0-9_-]{20,}\s*$", re.M)),
]
# Fichiers qui ne doivent jamais être suivis, quel que soit leur contenu.
INTERDITS = re.compile(r"(^|/)(\.env(\.[^/]*)?|id_rsa|id_ed25519|[^/]*\.p12|[^/]*\.pfx)$")
PERMIS = {".env.example"}
# Certificats publics de test (pas de clé privée) : autorisés.
TIRET = "—"


def exemple(label: str, text: str, m: re.Match) -> bool:
    """Valeurs de test publiques, pas des secrets : la clé d'exemple de la documentation AWS (suffixe « EXAMPLE ») et
    les blocs PEM factices des tests de refus (une vraie clé privée fait plusieurs centaines de caractères)."""
    if label.startswith("clé d'accès") and m.group(0).endswith("EXAMPLE"):
        return True
    if label == "clé privée PEM":
        end = text.find("-----END", m.end())
        return end != -1 and end - m.end() < 120
    return False


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode().split("\0") if p]


def main() -> int:
    problems = []
    for path in tracked():
        name = path.rsplit("/", 1)[-1]
        if INTERDITS.search(path) and name not in PERMIS:
            problems.append(f"{path} : fichier qui ne doit pas être suivi par git")
            continue
        try:
            with open(path, encoding="utf-8") as f:
                text = f.read()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue  # binaire ou supprimé de l'arbre de travail
        for label, rx in SECRETS:
            for m in rx.finditer(text):
                if exemple(label, text, m):
                    continue
                line = text.count("\n", 0, m.start()) + 1
                problems.append(f"{path}:{line} : {label} probable")
        if path.endswith(".md") and TIRET in text:
            for i, ligne in enumerate(text.splitlines(), 1):
                if TIRET in ligne:
                    problems.append(f"{path}:{i} : tiret cadratin dans la documentation")
    for p in problems:
        print(p)
    print(f"{len(problems)} problème(s)." if problems else "Dépôt propre : aucun secret, aucun tiret cadratin en Markdown.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
