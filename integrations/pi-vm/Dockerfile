# pi-attach agent image for gantry VMs — node + the pi-attach-v1 branch
# build + guest bridge. Built by integrations/pi-vm/mkpiattach.sh, which
# stages the pi checkout into the build context as ./pi-repo.
#
# Everything network-dependent (npm ci, apt, model catalog) happens in
# THIS stage via the mirror registry + corporate proxy build args, so the
# result is platform-independent (host node_modules arch is irrelevant).
ARG BASE=node:24-bookworm-slim
FROM ${BASE}

ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ARG REGISTRY=""
ARG CA_DIR=ca

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates git ripgrep fd-find \
 && rm -rf /var/lib/apt/lists/*

# Corporate TLS-inspection roots (Zscaler et al) into the system bundle —
# NODE_EXTRA_CA_CERTS below makes node trust them as well.
COPY ${CA_DIR}/ /tmp/ca/
RUN if ls /tmp/ca/*.pem >/dev/null 2>&1; then cat /tmp/ca/*.pem >> /etc/ssl/certs/ca-certificates.crt; fi
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

WORKDIR /opt/pi/repo
COPY pi-repo/ ./
RUN if [ -n "$REGISTRY" ]; then \
      npm config set registry "$REGISTRY" \
      && npm config set @typescript:registry "$REGISTRY"; \
    fi \
 && npm ci \
 && npm run build:offline \
 && npm prune --omit=dev

COPY bridge.js /opt/pi/bridge.js

WORKDIR /workspace
CMD ["node", "/opt/pi/bridge.js"]
