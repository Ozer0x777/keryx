# Garage (stockage objet), image officielle de Deuxfleurs : un seul binaire, aucun interpréteur de commandes.
# Seul ajout : les dossiers de données appartiennent à un utilisateur sans privilège, pour que les volumes
# nommés montés dessus le soient aussi (pas de démarrage en root, pas de « chown » à l'exécution).
ARG GARAGE_IMAGE=dxflrs/garage:v1.3.1@sha256:58e68794286868230708803e50495bfe7d1d1c7b696e0c2dee99b03c524fc960
FROM ${GARAGE_IMAGE}
COPY --chown=10002:10002 vide/ /var/lib/garage/meta/
COPY --chown=10002:10002 vide/ /var/lib/garage/data/
USER 10002:10002
EXPOSE 3900
CMD ["/garage", "server"]
