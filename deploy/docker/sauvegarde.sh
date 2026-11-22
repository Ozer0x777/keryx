#!/bin/sh
# Profil « sauvegarde » : lance « keryx backup » à intervalle fixe et garde les N dernières archives.
# Exécuté dans le conteneur « sauvegarde » (image de Keryx). L'archive est chiffrée par Keryx (ADR-0015) :
# sans KERYX_SECRET_KEY elle est illisible. Ce volume est sur la même machine que Keryx : le copier ailleurs
# (docs/deploiement-docker.md, PDIS IV.3.6).
set -u
umask 077
DEST=/sauvegardes
INTERVALLE="${KERYX_BACKUP_INTERVAL_S:-86400}"
GARDER="${KERYX_BACKUP_KEEP:-14}"
TEMOIN=/tmp/derniere-sauvegarde-reussie
mkdir -p "$DEST/.tmp"

while :; do
    rm -rf "$DEST/.tmp"/* 2>/dev/null
    fichier="$DEST/keryx-$(date -u +%Y%m%dT%H%M%SZ).kxb"
    if python -m keryx.cli backup "$fichier"; then
        touch "$TEMOIN"
        # Ne garder que les $GARDER archives les plus récentes (les noms se trient par date).
        # shellcheck disable=SC2012  # noms produits ici même : lettres, chiffres et tirets seulement
        ls -1 "$DEST"/keryx-*.kxb 2>/dev/null | sort -r | tail -n +"$((GARDER + 1))" | while read -r ancien; do
            rm -f "$ancien" && echo "Ancienne sauvegarde supprimée : $ancien"
        done
    else
        rm -f "$fichier" "$TEMOIN"
        echo "ÉCHEC de la sauvegarde $(date -u +%Y-%m-%dT%H:%M:%SZ)" >&2
    fi
    sleep "$INTERVALLE" &
    wait $!
done
