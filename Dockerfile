# syntax=docker/dockerfile:1
#
# humifortis — Keycloak with the Humifortis risk-based auth connector
# preinstalled and enabled as a provider.
#
# Build:
#   docker build -t humifortis .
#
# Run:
#   docker run -p 8080:8080 \
#     -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
#     -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
#     -e HUMIFORTIS_API_KEY=humi_kc_prod_xxx \
#     humifortis start-dev
#
# See DOCKER.md for full configuration and production notes.

# Keep in sync with <keycloak.version> in pom.xml.
ARG KEYCLOAK_VERSION=26.8.1

########################################
# Stage 1 — build the connector JAR
########################################
FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /build

# Resolve dependencies first so they're cached across source-only changes.
COPY pom.xml .
RUN mvn -B -q dependency:go-offline || true

# Java sources; the device-collector JS bundle is committed under src/main/resources.
COPY src ./src

RUN mvn -B -q clean package -DskipTests

########################################
# Stage 2 — Keycloak with the connector installed
########################################
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}

LABEL org.opencontainers.image.title="humifortis" \
      org.opencontainers.image.description="Keycloak with the Humifortis risk-based auth connector preinstalled" \
      org.opencontainers.image.source="https://github.com/humifortis/humifortis-keycloak-connector" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /build/target/humifortis-keycloak-connector.jar /opt/keycloak/providers/humifortis-keycloak-connector.jar

# Non-secret defaults matching the connector's own fallbacks (see INSTALLATION.md).
# HUMIFORTIS_API_KEY is intentionally left unset — it's required and must be
# supplied at `docker run` / compose / orchestrator level, never baked into the image.
ENV HUMIFORTIS_API_URL=https://api.humifortis.educosmic.tech \
    HUMIFORTIS_TIMEOUT_MS=5000 \
    HUMIFORTIS_FALLBACK_ALLOW=true

# Bake the provider into an optimized build at image-build time so `start
# --optimized` doesn't need to re-run `build` on every container boot.
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
