# Keycloak « optimisé » : la phase de construction de Keycloak est faite ici, une fois, pour que le conteneur
# démarre avec une racine en lecture seule (sinon Keycloak réécrit /opt/keycloak/lib/quarkus à chaque démarrage).
ARG KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:26.8.2@sha256:7e66a96e4739239070aeaf72e4c5decf0f7f682cfc725b9f7ea2b336eaba38b3
FROM ${KEYCLOAK_IMAGE} AS construction
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true
RUN /opt/keycloak/bin/kc.sh build

FROM ${KEYCLOAK_IMAGE}
COPY --from=construction /opt/keycloak/ /opt/keycloak/
ENV KC_DB=postgres \
    KC_HEALTH_ENABLED=true
USER 1000
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
# Les realms de /opt/keycloak/data/import ne sont importés que s'ils n'existent pas encore.
CMD ["start", "--optimized", "--import-realm"]
