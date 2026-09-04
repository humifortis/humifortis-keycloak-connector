# Docker Image

The `humifortis` Docker image is a standard Keycloak image with the Humifortis
connector JAR already installed in `/opt/keycloak/providers/` and compiled
into the server via `kc.sh build` at image-build time. There's nothing else
to install — pick the `humifortis` login theme and enable the event listener
and authenticators as usual (see [INSTALLATION.md](INSTALLATION.md) steps 5–6).

## Build

```bash
docker build -t humifortis .
```

By default the image is built on `quay.io/keycloak/keycloak:23.0.3`, matching
the `keycloak.version` the connector is compiled against in `pom.xml`. To
target a different supported version (22.x–24.x):

```bash
docker build --build-arg KEYCLOAK_VERSION=24.0.5 -t humifortis:24 .
```

## Run

```bash
docker run -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -e HUMIFORTIS_API_KEY=humi_kc_prod_xxx \
  humifortis start-dev
```

Or with Docker Compose (dev mode, in-memory H2 store — fine for trying things
out, not for production):

```bash
export HUMIFORTIS_API_KEY=humi_kc_prod_xxx
docker compose up --build
```

## Configuration

Same environment variables as a manual install (see
[INSTALLATION.md](INSTALLATION.md#configuration-reference)):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HUMIFORTIS_API_KEY` | **Yes** | — | API key from your connector registration in the Humifortis SaaS dashboard |
| `HUMIFORTIS_API_URL` | No | `https://api.humifortis.educosmic.tech` | SaaS API endpoint |
| `HUMIFORTIS_TIMEOUT_MS` | No | `5000` | HTTP timeout in milliseconds |
| `HUMIFORTIS_FALLBACK_ALLOW` | No | `true` | Allow access if the SaaS is unreachable |

`HUMIFORTIS_API_KEY` has no default baked into the image on purpose — supply
it via `-e`, a compose `environment:`/`.env` file, or a Kubernetes `Secret`,
never at build time.

## Production notes

The image runs `kc.sh build` during the Docker build, so the container's
default command is `start --optimized`. That means:

- Any build-time Keycloak options (database vendor, features, health/metrics,
  hostname strict mode, etc.) must be set as build args / `ENV` in a derived
  Dockerfile, or passed with a plain `kc.sh build` re-run — `--optimized`
  skips re-augmentation.
- Configure a real database (`KC_DB`, `KC_DB_URL`, ...) and hostname settings
  for anything beyond local testing — see the
  [Keycloak Guides](https://www.keycloak.org/server/containers) for the full
  set of production options; nothing here is Humifortis-specific.

## Kubernetes

The image works with any standard Keycloak Kubernetes deployment or the
Keycloak Operator — mount `HUMIFORTIS_API_KEY` from a `Secret` as shown in
[INSTALLATION.md](INSTALLATION.md#for-kubernetes). No init container or
extra volume is needed since the provider is already baked into the image.
