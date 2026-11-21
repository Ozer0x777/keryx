#!/bin/sh
# Initialise un Garage neuf pour Keryx : disposition du cluster, bucket, clé d'accès dédiée, et affiche les variables
# d'environnement de Keryx. Usage : GARAGE_BIN=garage GARAGE_CONF=/etc/garage.toml ZONE=dc1 CAPACITY=100G ./init.sh [bucket]
set -eu
G="${GARAGE_BIN:-garage} -c ${GARAGE_CONF:-/etc/garage.toml}"
BUCKET="${1:-keryx-pieces}"
ZONE="${ZONE:-dc1}"; CAPACITY="${CAPACITY:-100G}"
for i in $(seq 1 30); do $G status >/dev/null 2>&1 && break; sleep 1; done
NODE=$($G status 2>/dev/null | awk '/127\.0\.0\.1|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/ && $1 ~ /^[0-9a-f]{16}$/ {print $1; exit}')
[ -n "$NODE" ] || { echo "Nœud Garage introuvable (le serveur tourne-t-il ?)" >&2; exit 1; }
if $G layout show 2>/dev/null | grep -q "No nodes"; then :; fi
$G layout assign -z "$ZONE" -c "$CAPACITY" "$NODE" >/dev/null
VERSION=$($G layout show 2>/dev/null | awk '/apply --version/ {print $NF; exit}')
$G layout apply --version "${VERSION:-1}" >/dev/null
$G bucket create "$BUCKET" >/dev/null
OUT=$($G key create keryx-key)
KEYID=$(echo "$OUT" | awk '/Key ID:/ {print $3}'); SECRET=$(echo "$OUT" | awk '/Secret key:/ {print $3}')
$G bucket allow --read --write --owner "$BUCKET" --key keryx-key >/dev/null
cat <<ENV
# À placer dans l'environnement de Keryx (adresse en HTTPS derrière votre proxy TLS) :
KERYX_STORAGE=s3
KERYX_S3_ENDPOINT=https://s3.garage.interne
KERYX_S3_BUCKET=$BUCKET
KERYX_S3_ACCESS_KEY=$KEYID
KERYX_S3_SECRET_KEY=$SECRET
KERYX_S3_REGION=garage
ENV
