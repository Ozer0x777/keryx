"""Contrôle DCO (Developer Certificate of Origin, https://developercertificate.org/) d'une demande de fusion.

Chaque commit entre la base et la tête de la demande doit porter une ligne « Signed-off-by: Nom <adresse> » au nom
ou à l'adresse de son auteur (`git commit -s`). Les commits de fusion sont ignorés.
Usage : python3 scripts/verif_dco.py <empreinte de base> <empreinte de tête>
"""
import re
import subprocess
import sys

EMPREINTE = re.compile(r"^[0-9a-f]{40}$")
SIGNATURE = re.compile(r"^Signed-off-by: *(.+?) *<([^<>\s]+)> *$", re.M)


def signe(message: str, nom: str, adresse: str) -> bool:
    """Vrai si le message porte une attestation DCO de l'auteur (même adresse, ou même nom pour un robot)."""
    for nom_signe, adresse_signee in SIGNATURE.findall(message):
        if adresse_signee.lower() == adresse.strip().lower() or nom_signe == nom.strip():
            return True
    return False


def commits(base: str, tete: str) -> list[str]:
    sortie = subprocess.run(["git", "rev-list", "--no-merges", "--reverse", f"{base}..{tete}"],
                            capture_output=True, text=True, check=True).stdout
    return sortie.split()


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not all(EMPREINTE.match(a) for a in argv):
        print("Usage : verif_dco.py <empreinte de base> <empreinte de tête> (40 caractères hexadécimaux).")
        return 2
    manquants = []
    for empreinte in commits(*argv):
        nom, adresse, message = subprocess.run(
            ["git", "show", "-s", "--format=%an%x00%ae%x00%B", empreinte],
            capture_output=True, text=True, check=True).stdout.split("\x00", 2)
        if not signe(message, nom, adresse):
            manquants.append(f"{empreinte[:12]} {nom} : {message.splitlines()[0] if message else ''}")
    if manquants:
        print("Commits sans attestation DCO (« Signed-off-by: » de l'auteur, voir CONTRIBUTING.md) :")
        print("\n".join(f"  {m}" for m in manquants))
        print("Corriger : git rebase --signoff <base> puis pousser la branche à nouveau.")
        return 1
    print("DCO : chaque commit porte l'attestation de son auteur.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
