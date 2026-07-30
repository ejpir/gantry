# pi-attach agent container: runs `pi --mode rpc --sock ...` so a host TUI
# can attach with `pi attach --sock/--cmd` (agent-in-guest, thin-client host).
#
# Platform-independent: dependencies are installed and all packages are built
# INSIDE the image, so the host's node_modules state/arch does not matter.
# Build context must be the pi monorepo root:
#   ./pi-container.sh build

ARG BASE=nn-docker-remote.artifactory.insim.biz/library/node:24-slim
# Egress proxy for npm ci during the build (dev sandbox:
# http://gateway.docker.internal:3128; direct-egress hosts: leave empty).
ARG PROXY=""

# ---------------------------------------------------------------------------
# build stage: npm ci + full monorepo build
# ---------------------------------------------------------------------------
FROM ${BASE} AS build
ARG PROXY

COPY .pi-container/certs/ /opt/corp-certs/
RUN cat /opt/corp-certs/*.crt > /opt/corp-ca-bundle.crt
ENV NODE_EXTRA_CA_CERTS=/opt/corp-ca-bundle.crt
ENV HTTPS_PROXY=${PROXY} HTTP_PROXY=${PROXY} NO_PROXY=localhost,127.0.0.1,::1

WORKDIR /opt/pi
COPY . .
# Optional native deps (ssh2/crypto) build without a toolchain only via
# prebuilds; failures are tolerated by npm and fall back to pure JS.
RUN npm ci --no-audit --no-fund --maxsockets=4 --fetch-retries=5 \
      --fetch-retry-mintimeout=2000 --fetch-retry-maxtimeout=60000
RUN npm run build:offline
RUN npm prune --omit=dev

# ---------------------------------------------------------------------------
# runtime stage
# ---------------------------------------------------------------------------
FROM ${BASE}

# Corporate MITM (Zscaler) CA bundle so the agent can reach LLM APIs through
# the intercepting proxy (node:slim ships no system CA bundle file).
# The proxy address itself is supplied at `run` time (-e HTTPS_PROXY=...).
COPY .pi-container/certs/ /opt/corp-certs/
RUN cat /opt/corp-certs/*.crt > /opt/corp-ca-bundle.crt
ENV NODE_EXTRA_CA_CERTS=/opt/corp-ca-bundle.crt

WORKDIR /opt/pi
COPY --from=build /opt/pi .

# Minimal agent config (provider/model/theme only — no host extension paths).
# auth.json is bind-mounted at runtime (read-write: OAuth tokens refresh).
COPY .pi-container/settings.json /home/node/.pi/agent/settings.json
RUN mkdir -p /home/node/.pi/agent/sessions && chown -R node:node /home/node/.pi

USER node
ENTRYPOINT ["node", "/opt/pi/packages/coding-agent/dist/cli.js"]
CMD ["--mode", "rpc", "--sock", "/sock/agent.sock"]
