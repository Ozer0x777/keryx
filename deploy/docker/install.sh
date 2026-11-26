#!/bin/sh
# Installe et démarre Keryx avec Docker. Relançable : ne remplace jamais un fichier .env existant, ne recrée
# ni le compte Admin ni la clé du stockage objet. Mode d'emploi : README.md ; référence : docs/deploiement-docker.md.
#
#   ./install.sh                      pose les questions
#   KERYX_DOMAIN=… ./install.sh       les réponses fournies en variables ne sont pas demandées
#   KERYX_NON_INTERACTIF=1 …          ne demande rien (valeurs en variables, sinon valeurs par défaut)
#
# Variables lues (première installation) :
#   KERYX_HTTPS_MODE   acme | fourni | local                       (défaut : local)
#   KERYX_DOMAIN       nom de domaine ou adresse IPv4 (IP : modes local et fourni, pas acme) (défaut : localhost en mode local)
#   KERYX_PROFILES     antivirus,sso,objets,sauvegarde             (défaut : aucun)
#   KERYX_SSO_DOMAIN   nom de domaine de Keycloak, profil sso      (défaut : sso.localhost en mode local)
#   KERYX_ACME_CA      adresse de l'annuaire ACME, mode acme       (obligatoire, pas de valeur par défaut)
#   KERYX_ACME_EMAIL, KERYX_ACME_EAB_KID, KERYX_ACME_EAB_HMAC      (selon l'autorité)
#   KERYX_HTTP_PORT, KERYX_HTTPS_PORT, KERYX_LISTEN_ADDR           (défaut : 80, 443, toutes les adresses)
#   KERYX_SORTIES      oui | non : sorties de Keryx (SMTP, horodatage, indexeur Wazuh, syslog, VirusTotal) (défaut : non)
#   KERYX_PROJECT      nom du projet compose                       (défaut : keryx)
#   KERYX_ADMIN_USER   identifiant du premier compte Admin         (défaut : admin)
#   KERYX_IMAGE        image publiée à récupérer au lieu de construire (ex. ghcr.io/ozer0x777/keryx)
set -eu

ICI=$(cd "$(dirname "$0")" && pwd)
cd "$ICI"
ENVF="$ICI/.env"
PROFILS_CONNUS="antivirus sso objets sauvegarde"

dire()   { printf '%s\n' "$*"; }
titre()  { printf '\n== %s\n' "$*"; }
erreur() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }

avertir_secrets() {
    cat <<EOF

  !! SAUVEGARDER MAINTENANT, hors de cette machine : $ENVF
  !! Il contient KERYX_SECRET_KEY, la clé maîtresse. Si elle est perdue, sont perdus sans recours : les secrets
  !! TOTP de tous les comptes, les clés VirusTotal des analystes, les comptes de lecture des indexeurs Wazuh,
  !! les pièces du stockage objet et toutes les sauvegardes « keryx backup ».
  !! Sauvegarder aussi les volumes Docker (base, pièces) : voir README.md, « Sauvegarder ».
EOF
}

# ------------------------------------------------------------------------------------------------ outils
env_lire() {       # env_lire NOM : valeur de NOM dans .env (dernière définition, guillemets simples retirés)
    [ -f "$ENVF" ] || return 0
    sed -n "s/^$1=//p" "$ENVF" | tail -n 1 | sed "s/^'\\(.*\\)'\$/\\1/"
}
env_a() { [ -f "$ENVF" ] && grep -q "^$1=" "$ENVF"; }
env_ajouter() {    # env_ajouter NOM VALEUR [commentaire] : ajoute seulement si NOM est absent (rien n'est modifié)
    if env_a "$1"; then return 0; fi
    [ -n "${3:-}" ] && printf '# %s\n' "$3" >> "$ENVF"
    printf '%s=%s\n' "$1" "$2" >> "$ENVF"
}
alea() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }     # $1 octets aléatoires, en hexadécimal

demander() {       # demander VARIABLE "question" "défaut" : garde la valeur déjà fournie, sinon demande, sinon défaut
    eval "_v=\${$1:-}"
    if [ -z "$_v" ] && [ "$INTERACTIF" = 1 ]; then
        printf '%s [%s] : ' "$2" "$3"
        read -r _v || _v=""
    fi
    [ -n "$_v" ] || _v="$3"
    eval "$1=\$_v"
}
a_profil() { case ",$PROFILS," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
dc() { docker compose "$@"; }

attendre() {       # attendre "libellé" SECONDES commande… : relance la commande jusqu'à ce qu'elle réussisse
    _quoi=$1; _max=$2; shift 2; _n=0
    printf '   attente : %s ' "$_quoi"
    until "$@" >/dev/null 2>&1; do
        _n=$((_n + 3))
        if [ "$_n" -ge "$_max" ]; then
            printf ' délai dépassé (%s s)\n' "$_max"
            return 1
        fi
        printf '.'
        sleep 3
    done
    printf ' prêt\n'
}
sain() { [ "$(docker inspect --format '{{.State.Health.Status}}' "$(dc ps -q "$1" 2>/dev/null | head -n 1)" 2>/dev/null)" = healthy ]; }

# Requête HTTPS à travers le reverse proxy, depuis le conteneur keryx (aucun outil requis sur l'hôte). Le certificat
# n'est pas contrôlé ici : c'est un contrôle de bon fonctionnement (en mode acme il peut ne pas être encore délivré).
par_le_proxy() {
    dc exec -T keryx python -c '
import socket, ssl, sys
ip, port, host = sys.argv[1], int(sys.argv[2]), sys.argv[3]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((ip, port), timeout=5), server_hostname=host)
s.sendall(("GET /healthz HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
sys.exit(0 if s.recv(4096).split(b"\r\n")[0].endswith(b" 200 OK") else 1)
' "$PROXY_IP" "$PORT_HTTPS" "$DOMAINE"
}

# ------------------------------------------------------------------------------------------------ prérequis
titre "Prérequis"
command -v docker >/dev/null 2>&1 || erreur "docker est introuvable. Installer Docker Engine (docs.docker.com/engine/install)."
docker compose version >/dev/null 2>&1 || erreur "« docker compose » (version 2) est introuvable. Installer le greffon docker-compose-plugin."
docker info >/dev/null 2>&1 || erreur "le démon Docker ne répond pas (est-il démarré ? cet utilisateur y a-t-il accès ?)."
V=$(docker compose version --short 2>/dev/null | sed 's/^v//')
case "$V" in
    1.*|2.[0-9].*|2.1[0-9].*|2.2[0-3].*) erreur "docker compose $V est trop ancien : version 2.24 ou plus récente requise." ;;
esac
dire "   docker $(docker version --format '{{.Server.Version}}'), compose $V"

INTERACTIF=1
if [ -n "${KERYX_NON_INTERACTIF:-}" ] || [ ! -t 0 ]; then INTERACTIF=0; fi

# Les réponses données en variables sont recopiées ici, puis TOUTES les variables que docker-compose.yml lit sont
# retirées de l'environnement de ce script : pour « docker compose », une variable de l'environnement l'emporte sur
# .env, et un simple KERYX_DOMAIN=… resté dans le terminal reconfigurerait un déploiement existant.
D_MODE=${KERYX_HTTPS_MODE:-}; D_DOMAINE=${KERYX_DOMAIN:-}; D_SSO=${KERYX_SSO_DOMAIN:-}
D_PROFILS=${KERYX_PROFILES:-}; D_PROFILS_DONNES=${KERYX_PROFILES+oui}
D_ACME_CA=${KERYX_ACME_CA:-}; D_ACME_EMAIL=${KERYX_ACME_EMAIL:-}
D_EAB_KID=${KERYX_ACME_EAB_KID:-}; D_EAB_HMAC=${KERYX_ACME_EAB_HMAC:-}
D_HTTP=${KERYX_HTTP_PORT:-}; D_HTTPS=${KERYX_HTTPS_PORT:-}; D_ECOUTE=${KERYX_LISTEN_ADDR:-}
D_SORTIES=${KERYX_SORTIES:-}; D_PROJET=${KERYX_PROJECT:-keryx}; D_ADMIN=${KERYX_ADMIN_USER:-admin}
D_CAPACITE=${KERYX_GARAGE_CAPACITY:-10G}; D_IMAGE=${KERYX_IMAGE:-}
for v in $(env | sed -n -e 's/^\(KERYX_[A-Za-z0-9_]*\)=.*/\1/p' -e 's/^\(POSTGRES_[A-Za-z0-9_]*\)=.*/\1/p' \
                       -e 's/^\(KEYCLOAK_[A-Za-z0-9_]*\)=.*/\1/p' -e 's/^\(GARAGE_[A-Za-z0-9_]*\)=.*/\1/p' \
                       -e 's/^\(COMPOSE_[A-Za-z0-9_]*\)=.*/\1/p'); do
    unset "$v"
done

# ------------------------------------------------------------------------------------------------ réglages
NOUVEAU=1
if [ -f "$ENVF" ]; then
    NOUVEAU=0
    titre "Fichier .env existant : il est conservé tel quel, les réponses données en variables ne le modifient pas"
    for paire in "KERYX_DOMAIN=$D_DOMAINE" "KERYX_HTTPS_MODE=$D_MODE" "KERYX_SSO_DOMAIN=$D_SSO" "KERYX_HTTP_PORT=$D_HTTP" \
                 "KERYX_HTTPS_PORT=$D_HTTPS" "KERYX_ACME_CA=$D_ACME_CA"; do
        v=${paire%%=*}; _donne=${paire#*=}; _garde=$(env_lire "$v")
        if [ -n "$_donne" ] && [ "$_donne" != "$_garde" ]; then
            dire "   $v=$_donne est ignoré : .env contient déjà « $_garde » (modifier .env pour le changer)."
        fi
    done
    MODE=$(env_lire KERYX_HTTPS_MODE); DOMAINE=$(env_lire KERYX_DOMAIN)
    PROFILS=$(env_lire COMPOSE_PROFILES)
    if [ -n "$D_PROFILS" ] && [ "$D_PROFILS" != "$PROFILS" ]; then
        dire "   KERYX_PROFILES=$D_PROFILS est ignoré : .env contient « $PROFILS ». Pour ajouter un profil, modifier COMPOSE_PROFILES dans .env puis relancer ce script."
    fi
    SSO_DOMAINE=$(env_lire KERYX_SSO_DOMAIN)
    ACME_CA=$(env_lire KERYX_ACME_CA)
    PORT_HTTP=$(env_lire KERYX_HTTP_PORT); PORT_HTTPS=$(env_lire KERYX_HTTPS_PORT)
else
    titre "Réglages"
    MODE=$D_MODE
    demander MODE "Mode HTTPS : acme (certificat automatique), fourni (votre certificat), local (essai sur cette machine)" local
    case "$MODE" in acme|fourni|local) ;; *) erreur "mode HTTPS inconnu : $MODE (acme, fourni ou local)." ;; esac
    DOMAINE=$D_DOMAINE
    if [ "$MODE" = local ]; then
        demander DOMAINE "Nom de domaine ou adresse IP de Keryx" localhost
    else
        demander DOMAINE "Nom de domaine de Keryx (ex. keryx.exemple.eu)" ""
        [ -n "$DOMAINE" ] || erreur "un nom de domaine est requis en mode $MODE (KERYX_DOMAIN)."
    fi
    PROFILS=$D_PROFILS
    if [ -z "$D_PROFILS_DONNES" ] && [ "$INTERACTIF" = 1 ]; then
        dire "Profils facultatifs, séparés par des virgules (vide = aucun) :"
        dire "   antivirus   ClamAV. Ses signatures sont téléchargées depuis database.clamav.net (Cisco, États-Unis)."
        dire "   sso         Keycloak : realms « soc » et « clients », second facteur OTP exigé."
        dire "   objets      Garage : stockage objet des pièces (un seul nœud : essai)."
        dire "   sauvegarde  « keryx backup » chaque jour, dans un volume dédié."
        printf 'Profils [] : '
        read -r PROFILS || PROFILS=""
    fi
    PROFILS=$(printf '%s' "$PROFILS" | tr -d ' ')
    SSO_DOMAINE=$D_SSO
    ACME_CA=$D_ACME_CA
    PORT_HTTP=$D_HTTP; PORT_HTTPS=$D_HTTPS
    [ "$PORT_HTTP" = 80 ] && PORT_HTTP=""
    [ "$PORT_HTTPS" = 443 ] && PORT_HTTPS=""        # 443 ne s'écrit pas : l'adresse publique ne doit pas porter « :443 »
fi

case "$DOMAINE" in ""|*[!A-Za-z0-9.-]*) erreur "nom de domaine invalide : « $DOMAINE »." ;; esac
# Adresse IPv4 : accès sans nom de domaine. Pas de certificat ACME automatique pour une adresse IP ici ; en mode
# fourni, le certificat doit porter cette adresse dans ses noms alternatifs (subjectAltName).
case "$DOMAINE" in
    *[!0-9.]*) ;;
    *) [ "$MODE" != acme ] || erreur "le mode acme demande un nom de domaine, pas une adresse IP ($DOMAINE). Utiliser le mode local ou fourni."
       dire "   Accès par adresse IP ($DOMAINE) : le certificat est vérifié contre cette adresse, pas contre un nom." ;;
esac
for p in $(printf '%s' "$PROFILS" | tr ',' ' '); do
    case " $PROFILS_CONNUS " in *" $p "*) ;; *) erreur "profil inconnu : $p (connus : $PROFILS_CONNUS)." ;; esac
done

if a_profil sso && [ -z "$SSO_DOMAINE" ]; then
    if [ "$MODE" = local ]; then
        demander SSO_DOMAINE "Nom de domaine de Keycloak" "sso.$DOMAINE"
    else
        demander SSO_DOMAINE "Nom de domaine de Keycloak (ex. sso.exemple.eu, distinct de celui de Keryx)" ""
    fi
    [ -n "$SSO_DOMAINE" ] || erreur "le profil sso demande un nom de domaine pour Keycloak (KERYX_SSO_DOMAIN)."
fi
case "$SSO_DOMAINE" in *[!A-Za-z0-9.-]*) erreur "nom de domaine invalide : « $SSO_DOMAINE »." ;; esac
[ -z "$SSO_DOMAINE" ] || [ "$SSO_DOMAINE" != "$DOMAINE" ] || erreur "Keycloak doit avoir un autre nom de domaine que Keryx."

if [ "$MODE" = acme ] && [ -z "$ACME_CA" ]; then
    dire "Mode acme : quelle autorité de certification ? Donner l'adresse de son annuaire ACME."
    dire "   Il n'y a pas de valeur par défaut : le projet n'admet aucun service hors de l'Union européenne sans décision"
    dire "   écrite. Let's Encrypt (https://acme-v02.api.letsencrypt.org/directory) est exploité aux États-Unis : le"
    dire "   choisir est une dérogation à consigner. Une autorité de l'UE fournit sa propre adresse, souvent avec une"
    dire "   liaison de compte (KERYX_ACME_EAB_KID, KERYX_ACME_EAB_HMAC). Voir docs/deploiement-docker.md."
    demander ACME_CA "Adresse de l'annuaire ACME" ""
    [ -n "$ACME_CA" ] || erreur "le mode acme demande KERYX_ACME_CA (adresse de l'annuaire ACME de l'autorité choisie)."
fi
case "$ACME_CA" in ""|https://*) ;; *) erreur "KERYX_ACME_CA doit commencer par https://." ;; esac

if [ "$MODE" = fourni ]; then
    for f in keryx.crt keryx.key; do
        [ -s "certs/$f" ] || erreur "mode fourni : déposer le certificat (chaîne complète) et sa clé dans $ICI/certs/keryx.crt et keryx.key."
    done
    if a_profil sso; then
        for f in sso.crt sso.key; do
            [ -s "certs/$f" ] || erreur "mode fourni avec le profil sso : déposer aussi $ICI/certs/sso.crt et sso.key (ou y copier keryx.* si le certificat couvre les deux noms)."
        done
    fi
fi

SUFFIXE=""; [ -z "$PORT_HTTPS" ] || SUFFIXE=":$PORT_HTTPS"
URL="https://$DOMAINE$SUFFIXE"

# ------------------------------------------------------------------------------------------------ image
titre "Image de Keryx"
# Image publiée (KERYX_IMAGE) : récupérée, et sa signature TOUJOURS vérifiée (cosign installé, sinon son image
# officielle épinglée par empreinte) ; sinon construite ici. Seule exception, explicite : KERYX_VERIFIER_SIGNATURE=non,
# pour une image copiée dans un registre interne après avoir été vérifiée (docs/publication.md, registre relais).
# Les deux variables exigées par docker-compose.yml n'existent pas encore à la première installation.
COSIGN_IMAGE="gcr.io/projectsigstore/cosign:v2.4.1@sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31"
cosign_verify() {
    if command -v cosign >/dev/null 2>&1; then cosign verify "$@"; else docker run --rm "$COSIGN_IMAGE" verify "$@"; fi
}
if [ "$NOUVEAU" = 1 ]; then PUBLIEE=$D_IMAGE; else PUBLIEE=$(env_lire KERYX_IMAGE); fi
dc_init() { if [ "$NOUVEAU" = 1 ]; then env KERYX_SECRET_KEY=construction POSTGRES_PASSWORD=construction KERYX_IMAGE="$PUBLIEE" docker compose "$@"; else dc "$@"; fi; }
if [ -n "$PUBLIEE" ]; then
    case "$PUBLIEE" in *[!A-Za-z0-9./_-]*) erreur "KERYX_IMAGE invalide : « $PUBLIEE »." ;; esac
    dc_init pull keryx
    IMAGE=$(dc_init config --images | grep -E '(^|/)keryx:' | head -n 1)
    case "${KERYX_VERIFIER_SIGNATURE:-oui}" in
        non)
            dire "   ATTENTION : signature de $IMAGE NON vérifiée (KERYX_VERIFIER_SIGNATURE=non). À réserver à une image"
            dire "   copiée dans un registre interne après vérification de sa signature (docs/publication.md)." ;;
        oui)
            DEPOT=$(printf '%s' "$PUBLIEE" | sed -n 's#^ghcr\.io/\([^/]*\)/\([^/]*\)$#\1/\2#p')
            [ -n "$DEPOT" ] || erreur "la signature se vérifie sur une image ghcr.io/<compte>/<dépôt> : « $PUBLIEE ». Image d'un registre interne, déjà vérifiée avant copie : relancer avec KERYX_VERIFIER_SIGNATURE=non."
            cosign_verify "$IMAGE" --certificate-oidc-issuer https://token.actions.githubusercontent.com \
                --certificate-identity-regexp "(?i)^https://github.com/$DEPOT/\.github/workflows/publication\.yml@refs/tags/v" >/dev/null \
                || erreur "signature de $IMAGE invalide ou absente : image refusée."
            dire "   signature de $IMAGE vérifiée (publiée par le dépôt $DEPOT)." ;;
        *) erreur "KERYX_VERIFIER_SIGNATURE vaut « oui » (par défaut) ou « non »." ;;
    esac
else
    dc_init build keryx
    IMAGE=$(dc_init config --images | grep -E '(^|/)keryx:' | head -n 1)
fi
[ -n "$IMAGE" ] || erreur "nom de l'image de Keryx introuvable (docker compose config --images)."

# ------------------------------------------------------------------------------------------------ .env
if [ "$NOUVEAU" = 1 ]; then
    titre "Écriture de .env (secrets)"
    # Clé maîtresse : produite par la commande du projet, dans un conteneur sans réseau.
    CLE=$(docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
              --user 10001:10001 "$IMAGE" python -m keryx.cli gen-key) || erreur "« keryx gen-key » a échoué."
    [ "${#CLE}" -ge 40 ] || erreur "clé maîtresse inattendue (« keryx gen-key »)."
    SORTIES=$D_SORTIES
    demander SORTIES "Ouvrir les sorties réseau de Keryx (SMTP, horodatage, indexeur Wazuh, syslog, VirusTotal) ? oui/non" non
    case "$SORTIES" in oui|o|O|yes|y) FERMEE=false ;; *) FERMEE=true ;; esac
    # Le conteneur caddy tourne sous l'utilisateur qui installe (il lit ainsi ./certs sans droit particulier),
    # jamais sous root.
    CUID=$(id -u); CGID=$(id -g)
    if [ "$CUID" = 0 ]; then
        CUID=10003; CGID=10003
        [ "$MODE" != fourni ] || chown -R 10003:10003 certs
    fi
    umask 077
    TMP="$ENVF.partiel.$$"
    cat > "$TMP" <<EOF
# Keryx : réglages et SECRETS de ce déploiement. Écrit par install.sh le $(date -u +%Y-%m-%dT%H:%M:%SZ).
# NE PAS COMMITER. À SAUVEGARDER hors de cette machine : sans KERYX_SECRET_KEY, les secrets chiffrés
# (TOTP, clés VirusTotal, comptes d'indexeur Wazuh), les pièces du stockage objet et les sauvegardes sont perdus.
# Ne jamais laisser une variable vide : la commenter. Toutes les variables : .env.example.

COMPOSE_PROJECT_NAME=$D_PROJET
COMPOSE_PROFILES=$PROFILS

KERYX_DOMAIN=$DOMAINE
KERYX_HTTPS_MODE=$MODE
KERYX_CADDY_UID=$CUID
KERYX_CADDY_GID=$CGID

KERYX_SECRET_KEY=$CLE
POSTGRES_PASSWORD=$(alea 24)

# Sorties réseau de Keryx (SMTP, horodatage, indexeur Wazuh, syslog, VirusTotal) : fermées si true.
KERYX_SORTIE_FERMEE=$FERMEE
# Recherche VirusTotal (service hors UE, dérogation ADR-0022). false dans un déploiement visant la qualification PDIS.
KERYX_VIRUSTOTAL_ENABLED=$([ "$FERMEE" = true ] && echo false || echo true)
EOF
    [ -z "$PORT_HTTP" ] || printf 'KERYX_HTTP_PORT=%s\n' "$PORT_HTTP" >> "$TMP"
    [ -z "$PORT_HTTPS" ] || printf 'KERYX_HTTPS_PORT=%s\n' "$PORT_HTTPS" >> "$TMP"
    [ -z "$D_ECOUTE" ] || printf 'KERYX_LISTEN_ADDR=%s\n' "$D_ECOUTE" >> "$TMP"
    if [ "$MODE" = acme ]; then
        printf 'KERYX_ACME_CA=%s\n' "$ACME_CA" >> "$TMP"
        [ -z "$D_ACME_EMAIL" ] || printf 'KERYX_ACME_EMAIL=%s\n' "$D_ACME_EMAIL" >> "$TMP"
        [ -z "$D_EAB_KID" ] || printf 'KERYX_ACME_EAB_KID=%s\nKERYX_ACME_EAB_HMAC=%s\n' "$D_EAB_KID" "$D_EAB_HMAC" >> "$TMP"
    fi
    [ -z "$PUBLIEE" ] || printf '# Image publiée de Keryx (récupérée, non construite ici)\nKERYX_IMAGE=%s\n' "$PUBLIEE" >> "$TMP"
    # Jamais d'écrasement : si un .env est apparu entre-temps, on s'arrête.
    if ! ln "$TMP" "$ENVF" 2>/dev/null; then
        rm -f "$TMP"
        erreur ".env existe déjà : il n'a pas été modifié. Relancer le script."
    fi
    rm -f "$TMP"
    avertir_secrets
fi
chmod 600 "$ENVF"

# Réglages des profils : ajoutés s'ils manquent (première installation, ou profil ajouté ensuite dans .env).
if a_profil antivirus; then
    env_ajouter KERYX_CLAMAV_HOST clamav "Profil antivirus"
fi
if a_profil sso; then
    env_ajouter KERYX_SSO_DOMAIN "$SSO_DOMAINE" "Profil sso (Keycloak)"
    env_ajouter KEYCLOAK_ADMIN_USER admin-keycloak
    env_ajouter KEYCLOAK_ADMIN_PASSWORD "$(alea 18)"
    env_ajouter KEYCLOAK_DB_PASSWORD "$(alea 24)"
    env_ajouter KERYX_OIDC_SECRET_SOC "$(alea 32)"
    env_ajouter KERYX_OIDC_SECRET_CLIENTS "$(alea 32)"
    EMETTEUR="https://$(env_lire KERYX_SSO_DOMAIN)$SUFFIXE/realms"
    # « roles » borne ce que chaque realm peut authentifier (ADR-0017) : jamais un Admin, jamais l'autre population.
    env_ajouter KERYX_OIDC_PROVIDERS "'[{\"name\":\"soc\",\"label\":\"Compte SOC\",\"issuer\":\"$EMETTEUR/soc\",\"client_id\":\"keryx\",\"client_secret\":\"$(env_lire KERYX_OIDC_SECRET_SOC)\",\"roles\":[\"manager\",\"analyst\"]},{\"name\":\"clients\",\"label\":\"Compte client\",\"issuer\":\"$EMETTEUR/clients\",\"client_id\":\"keryx\",\"client_secret\":\"$(env_lire KERYX_OIDC_SECRET_CLIENTS)\",\"roles\":[\"client\"]}]'"
fi
if a_profil objets; then
    env_ajouter GARAGE_RPC_SECRET "$(alea 32)" "Profil objets (Garage)"
fi

PREFIXE=$(env_lire KERYX_NET_PREFIX); PROXY_IP="${PREFIXE:-172.31.240}.2"
PORT_HTTPS=${PORT_HTTPS:-443}

# ------------------------------------------------------------------------------------------------ démarrage
titre "Construction des autres images et démarrage"
if [ -n "$PUBLIEE" ]; then
    # keryx et sauvegarde viennent de l'image publiée : seules les images propres au kit sont construites.
    for svc in $(dc config --services); do
        case "$svc" in keycloak|garage) dc build "$svc" ;; esac
    done
else
    dc build
fi
dc up -d postgres keryx caddy
attendre "Keryx (migrations, /healthz)" 180 sain keryx || { dc logs --tail 40 keryx; erreur "Keryx ne démarre pas (journal ci-dessus)."; }

# Autorité privée : Keryx doit reconnaître le certificat du reverse proxy pour joindre Keycloak par son adresse
# publique (mode local : autorité interne de Caddy ; mode fourni : déposer l'autorité dans certs/ca.crt).
if a_profil sso && ! env_a KERYX_CA_BUNDLE; then
    AC=""
    if [ "$MODE" = local ]; then
        attendre "autorité locale de Caddy" 60 dc exec -T caddy test -s /data/caddy/pki/authorities/local/root.crt \
            || erreur "l'autorité locale de Caddy n'a pas été créée."
        AC=$(dc exec -T caddy cat /data/caddy/pki/authorities/local/root.crt)
    elif [ "$MODE" = fourni ] && [ -s certs/ca.crt ]; then
        AC=$(cat certs/ca.crt)
    fi
    if [ -n "$AC" ]; then
        ( umask 022
          { dc exec -T keryx cat /etc/ssl/certs/ca-certificates.crt; printf '%s\n' "$AC"; } > confiance/ca-bundle.pem )
        env_ajouter KERYX_CA_BUNDLE /etc/keryx/confiance/ca-bundle.pem "Autorités reconnues par Keryx : celles du système et l'autorité privée du reverse proxy"
        dire "   autorité privée ajoutée à confiance/ca-bundle.pem"
    fi
fi

dc up -d
a_profil sso && { attendre "Keycloak (import des realms)" 300 sain keycloak || { dc logs --tail 40 keycloak; erreur "Keycloak ne démarre pas."; }; }

# Stockage objet : disposition, bucket et clé créés une fois par le script du dépôt, puis Keryx bascule dessus.
if a_profil objets && ! env_a KERYX_S3_ACCESS_KEY; then
    titre "Initialisation de Garage (deploy/garage/init.sh)"
    attendre "Garage" 90 dc exec -T garage /garage status || erreur "Garage ne répond pas."
    # Le script du dépôt appelle « garage » : ici, celui du conteneur (RUST_LOG=warn : sans ses lignes d'information).
    SORTIE=$(GARAGE_BIN="docker compose exec -T -e RUST_LOG=warn garage /garage" GARAGE_CONF=/etc/garage.toml CAPACITY="$D_CAPACITE" \
                 sh "$ICI/../garage/init.sh" keryx-pieces) || { printf '%s\n' "$SORTIE"; erreur "l'initialisation de Garage a échoué (voir docs/deploiement-docker.md, « Reprendre l'initialisation de Garage »)."; }
    AK=$(printf '%s\n' "$SORTIE" | sed -n 's/^KERYX_S3_ACCESS_KEY=//p'); SK=$(printf '%s\n' "$SORTIE" | sed -n 's/^KERYX_S3_SECRET_KEY=//p')
    { [ -n "$AK" ] && [ -n "$SK" ]; } || erreur "clé d'accès de Garage introuvable dans la sortie de init.sh."
    env_ajouter KERYX_STORAGE s3 "Profil objets : pièces dans Garage, chiffrées par Keryx avant envoi"
    env_ajouter KERYX_S3_ENDPOINT http://garage:3900
    env_ajouter KERYX_S3_ALLOW_HTTP true
    env_ajouter KERYX_S3_BUCKET keryx-pieces
    env_ajouter KERYX_S3_REGION garage
    env_ajouter KERYX_S3_ACCESS_KEY "$AK"
    env_ajouter KERYX_S3_SECRET_KEY "$SK"
    dc up -d
fi

# Après un changement de sous-réseau (KERYX_NET_PREFIX), Docker rebranche un conteneur existant sans son adresse
# fixe : le reverse proxy doit alors être recréé, sinon Keryx ne croirait plus ses en-têtes X-Forwarded-*.
adresse_proxy() { docker inspect --format '{{range $n, $c := .NetworkSettings.Networks}}{{$c.IPAddress}} {{end}}' "$(dc ps -q caddy | head -n 1)" 2>/dev/null; }
case " $(adresse_proxy) " in
    "  "|*" $PROXY_IP "*) ;;
    *) dire "   le reverse proxy n'a pas l'adresse $PROXY_IP : il est recréé"; dc up -d --force-recreate caddy ;;
esac

attendre "Keryx" 180 sain keryx || { dc logs --tail 40 keryx; erreur "Keryx ne démarre pas (journal ci-dessus)."; }
attendre "$URL/healthz à travers le reverse proxy" 120 par_le_proxy \
    || { dc logs --tail 6 caddy; erreur "le reverse proxy ne relaie pas /healthz (journal de caddy ci-dessus)."; }

# ------------------------------------------------------------------------------------------------ premier Admin
ADMIN=$D_ADMIN
NB=$(dc exec -T keryx python -c '
from sqlalchemy import func, select
from keryx.config import Settings
from keryx.db import make_engine, make_session_factory
from keryx.models import User
db = make_session_factory(make_engine(Settings().database_url))()
print(db.scalar(select(func.count()).select_from(User).where(User.role == "admin")))
') || erreur "lecture des comptes impossible."
if [ "$NB" = 0 ]; then
    titre "Premier compte Admin"
    MDP=$(alea 12)
    # Le mot de passe passe par l'entrée standard : il n'apparaît ni dans la liste des processus ni dans .env.
    # shellcheck disable=SC2016  # « $1 » est développé par le sh du conteneur, pas ici
    CREATION=$(printf '%s\n' "$MDP" | dc exec -T keryx sh -c \
        'read -r KERYX_NEW_PASSWORD && export KERYX_NEW_PASSWORD && exec python -m keryx.cli add-user "$1" "Administrateur" admin --activation' sh "$ADMIN") \
        || erreur "création du compte Admin impossible."
    CODE=$(printf '%s\n' "$CREATION" | tail -n 1 | tr -d ' ')
    cat <<EOF

  Ces trois valeurs ne seront PLUS JAMAIS affichées. Les noter maintenant.

     Adresse                  : $URL
     Identifiant              : $ADMIN
     Mot de passe temporaire  : $MDP
     Code d'activation        : $CODE     (usage unique, valable 72 h)

  À la première connexion : mot de passe temporaire, code d'activation, enrôlement de l'application TOTP,
  choix du mot de passe définitif, codes de secours à conserver.
  Code expiré ou perdu avant l'activation : créer un autre compte Admin (le mot de passe temporaire est demandé) :
     docker compose exec keryx python -m keryx.cli add-user admin2 "Administrateur" admin --activation
EOF
else
    titre "Compte Admin : déjà présent ($NB), rien n'est créé"
fi

# ------------------------------------------------------------------------------------------------ suite
titre "Keryx est démarré : $URL"
dc ps --format 'table {{.Service}}\t{{.Status}}'
[ "$MODE" != local ] || dire "
   Mode local : le navigateur signalera un certificat inconnu (autorité interne de Caddy). Pour l'accepter proprement :
      docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt > caddy-racine.crt   # puis l'importer"
if a_profil sso; then
    dire "
   Keycloak : https://$(env_lire KERYX_SSO_DOMAIN)$SUFFIXE/admin/   (compte $(env_lire KEYCLOAK_ADMIN_USER), mot de passe : KEYCLOAK_ADMIN_PASSWORD dans .env)
      C'est un compte d'amorçage : créer un administrateur nominatif avec second facteur, puis le supprimer.
      Créer les utilisateurs dans les realms « soc » et « clients », avec la MÊME adresse courriel (vérifiée) que leur compte Keryx."
fi
cat <<EOF

== Brancher Wazuh (détail : integrations/wazuh/README.md)

 1. Dans Keryx, connecté en Admin : Administration > Clients (créer le client), puis Administration > Clés d'API
    (une clé par manager Wazuh et par client ; elle n'est affichée qu'une fois). Ou en ligne de commande :
       docker compose exec keryx python -m keryx.cli add-client ACME "ACME Industrie"
       docker compose exec keryx python -m keryx.cli add-api-key ACME wazuh-manager-01
 2. Sur le manager Wazuh, copier les deux fichiers du dépôt
       $(cd "$ICI/../.." && pwd)/integrations/wazuh/custom-keryx
       $(cd "$ICI/../.." && pwd)/integrations/wazuh/custom-keryx.py
    dans /var/ossec/integrations/ (chmod 750, chown root:wazuh).
 3. Ajouter dans /var/ossec/etc/ossec.conf, puis « systemctl restart wazuh-manager » :

<integration>
  <name>custom-keryx</name>
  <hook_url>$URL/api/v1/ingest/wazuh</hook_url>
  <api_key>kx_REMPLACER_PAR_LA_CLE</api_key>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>

    Le manager doit résoudre « $DOMAINE » et joindre le port $PORT_HTTPS de cette machine. Le certificat est vérifié :
    avec une autorité privée (modes local et fourni), donner son certificat au script par KERYX_CA_BUNDLE.
EOF
avertir_secrets
dire "
   Arrêt : ./uninstall.sh (les volumes et .env sont conservés).  État : docker compose ps.  Journaux : docker compose logs -f keryx"
