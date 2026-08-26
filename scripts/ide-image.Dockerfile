FROM debian:bookworm-slim

# Keep the mirror explicit and overridable for proxied/corporate builds. The
# German Debian mirror provides a stable European endpoint; Debian Security's
# CDN remains the authoritative security archive.
ARG DEBIAN_MIRROR=http://ftp.de.debian.org/debian
ARG DEBIAN_SECURITY_MIRROR=http://security.debian.org/debian-security
RUN find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) -exec sed -i \
      -e "s|https\?://deb.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      -e "s|https\?://security.debian.org/debian-security|${DEBIAN_SECURITY_MIRROR}|g" \
      -e "s|https\?://deb.debian.org/debian|${DEBIAN_MIRROR}|g" {} + \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       bash buildah ca-certificates curl fuse-overlayfs git libnss-myhostname \
       libstdc++6 openssh-client podman slirp4netns sudo tar uidmap util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 gantry \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash gantry \
    && if ! grep -q '^hosts:.*myhostname' /etc/nsswitch.conf; then \
         sed -i '/^hosts:/ s/ files/ files myhostname/' /etc/nsswitch.conf; \
       fi \
    && printf 'gantry ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/gantry \
    && chmod 0440 /etc/sudoers.d/gantry \
    && visudo -cf /etc/sudoers.d/gantry

# Nested Podman cannot manage the VM's cgroup tree or writable kernel sysctls.
# Use userspace networking and suppress Podman's default sysctl writes. The
# launcher clears only stale /run state when Gantry boots a new VM; persistent
# images and volumes remain under /var/lib/containers.
COPY gantry-podman /usr/local/libexec/gantry-podman
RUN install -d -m 0755 /etc/containers/containers.conf.d \
    && printf '[containers]\ncgroups = "disabled"\nnetns = "slirp4netns"\ndefault_sysctls = []\n' \
       > /etc/containers/containers.conf.d/gantry.conf \
    && chmod 0755 /usr/local/libexec/gantry-podman \
    && printf '%s\n' \
       '#!/bin/sh' \
       'unset DOCKER_HOST DOCKER_CONTEXT CONTAINER_HOST XDG_RUNTIME_DIR' \
       'export BUILDAH_FORMAT=docker' \
       'exec sudo -n -H --preserve-env=HTTP_PROXY,HTTPS_PROXY,ALL_PROXY,NO_PROXY,http_proxy,https_proxy,all_proxy,no_proxy /usr/local/libexec/gantry-podman "$@"' \
       > /usr/local/bin/docker \
    && chmod 0755 /usr/local/bin/docker

USER gantry
WORKDIR /home/gantry
ENV HOME=/home/gantry
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CMD ["/bin/bash"]
