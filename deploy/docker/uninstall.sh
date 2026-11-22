#!/bin/sh
# Arrête Keryx. Par défaut RIEN n'est supprimé : ni les volumes (base, pièces, certificats, sauvegardes), ni .env.
#
#   ./uninstall.sh             arrête et retire les conteneurs et les réseaux ; ./install.sh ou
#                              « docker compose up -d » redémarre avec les mêmes données
#   ./uninstall.sh --purger    supprime AUSSI les volumes, après confirmation : données définitivement perdues
set -eu
cd "$(dirname "$0")"
[ -f .env ] || { echo "Aucun fichier .env ici : rien n'a été installé par install.sh." >&2; exit 1; }
PROJET=$(sed -n 's/^COMPOSE_PROJECT_NAME=//p' .env | tail -n 1); PROJET=${PROJET:-keryx}

case "${1:-}" in
    "")
        # --profile "*" : arrête aussi les services d'un profil retiré de .env depuis le démarrage.
        docker compose --profile "*" down
        echo
        echo "Keryx est arrêté. Volumes et .env conservés (docker volume ls --filter label=com.docker.compose.project=$PROJET)."
        ;;
    --purger)
        echo "Ceci SUPPRIME les volumes du projet « $PROJET » : base de données, pièces, certificats, sauvegardes du"
        echo "volume « sauvegardes », données de Keycloak et de Garage. Aucun retour possible."
        docker volume ls --filter "label=com.docker.compose.project=$PROJET" --format '   {{.Name}}'
        printf 'Pour confirmer, taper le nom du projet (%s) : ' "$PROJET"
        read -r REPONSE || REPONSE=""
        [ "$REPONSE" = "$PROJET" ] || { echo "Abandon : rien n'a été supprimé."; exit 1; }
        docker compose --profile "*" down --volumes
        echo
        echo "Conteneurs, réseaux et volumes supprimés. Le fichier .env est conservé : il contient la clé maîtresse,"
        echo "seule capable de relire les sauvegardes déjà exportées. Le supprimer à la main s'il ne sert plus."
        ;;
    *)
        echo "Usage : $0 [--purger]" >&2
        exit 2
        ;;
esac
