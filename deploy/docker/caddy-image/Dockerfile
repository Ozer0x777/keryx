# Caddy avec le pare-feu applicatif Coraza et l'OWASP Core Rule Set (PDIS IV.3.13.g ; docs/deploiement-docker.md).
# Construit par xcaddy à partir de l'image officielle de construction de Caddy, épinglée par empreinte. Les modules Go
# sont vérifiés par la base de sommes publique de Go (sum.golang.org) : un module modifié après coup est refusé.
# Le CRS est embarqué dans le module (coraza-coreruleset), aucun fichier de règles n'est téléchargé au démarrage.
ARG CADDY_BUILDER=caddy:2.11.9-builder-alpine@sha256:86e132d1d6db8850352b2dbc15f82a4cb25363ac305ee41e11405873e5931f37
ARG CADDY_IMAGE=caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
ARG CORAZA_CADDY=v2.6.2

FROM ${CADDY_BUILDER} AS construction
ARG CORAZA_CADDY
ENV GOFLAGS=-trimpath
RUN xcaddy build v2.11.9 --with github.com/corazawaf/coraza-caddy/v2@${CORAZA_CADDY} --output /usr/bin/caddy-coraza \
 && /usr/bin/caddy-coraza list-modules | grep -q '^http.handlers.waf$'

FROM ${CADDY_IMAGE}
COPY --from=construction /usr/bin/caddy-coraza /usr/bin/caddy
