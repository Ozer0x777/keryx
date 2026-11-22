# Keryx : un conteneur (API + interface web construite). Base : SQLite en test, PostgreSQL en production.
# Étape 1 : construction de l'interface web (aucun fichier n'est chargé depuis un CDN à l'exécution).
FROM node:22-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web ./
RUN npm run build -- --outDir dist --emptyOutDir

# Étape 2 : application
FROM python:3.12-slim
# /sauvegardes : point de montage du volume de « keryx backup » (deploy/docker, profil sauvegarde). Le créer ici, au
# bon propriétaire, évite tout « chown » à l'exécution : le volume nommé monté dessus en hérite.
RUN useradd --create-home --uid 10001 keryx \
 && mkdir -p /data/attachments /sauvegardes \
 && chown -R 10001:10001 /data /sauvegardes && chmod 700 /data /sauvegardes
# Client PostgreSQL : nécessaire à « keryx backup » / « keryx restore » quand la base est PostgreSQL.
# ca-certificates : autorités du système, contre lesquelles le certificat de VirusTotal est vérifié (ADR-0022).
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY keryx ./keryx
COPY alembic.ini ./
COPY migrations ./migrations
COPY --from=web /web/dist ./keryx/web_dist
USER keryx
ENV KERYX_DATABASE_URL=sqlite:////data/keryx.db \
    KERYX_ATTACHMENTS_DIR=/data/attachments \
    FORWARDED_ALLOW_IPS=127.0.0.1
# FORWARDED_ALLOW_IPS : remplacer par l'adresse du reverse proxy (jamais « * »), sinon toutes les
# requêtes semblent venir du proxy et la limitation de débit devient commune à tous.
VOLUME ["/data"]
EXPOSE 8000
# Migrations puis démarrage. TLS terminé par le reverse proxy (TLS 1.2 minimum, 1.3 préféré — RFC 9325).
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn keryx.api:create_app --factory --host 0.0.0.0 --port 8000 --proxy-headers"]
