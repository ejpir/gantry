## pi-attach agent container: runs `pi --mode rpc --sock ...` so a host TUI
# can attach with `pi attach --sock` (agent-in-guest, thin-client host).
#
# Build context must be the pi monorepo root (with dist/ and node_modules/
# already built/installed for linux-arm64):
#   ./pi-container.sh build
FROM nn-docker-remote.artifactory.insim.biz/library/node:22-slim

# Corporate MITM (Zscaler) CA bundle, staged into the context by the script,
# so the agent can reach LLM APIs through the intercepting proxy.
COPY .pi-container/certs/ /opt/corp-certs/
RUN cat /opt/corp-certs/*.crt > /opt/corp-ca-bundle.crt
ENV NODE_EXTRA_CA_CERTS=/opt/corp-ca-bundle.crt

# LLM/API egress via the corporate proxy (reachable from the container's
# default bridge through NAT).
ENV HTTPS_PROXY=http://192.168.1.1:3128 \
    HTTP_PROXY=http://192.168.1.1:3128 \
    NO_PROXY=localhost,127.0.0.1,::1

WORKDIR /opt/pi
COPY . .

# Minimal agent config (provider/model/theme only — no host extension paths).
# auth.json is bind-mounted at runtime (read-write: OAuth tokens refresh).
COPY .pi-container/settings.json /home/node/.pi/agent/settings.json
RUN mkdir -p /home/node/.pi/agent/sessions && chown -R node:node /home/node/.pi

USER node
ENTRYPOINT ["node", "/opt/pi/packages/coding-agent/dist/cli.js"]
CMD ["--mode", "rpc", "--sock", "/sock/agent.sock"]
