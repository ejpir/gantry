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
       bash ca-certificates curl git libstdc++6 openssh-client sudo tar \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 gantry \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash gantry \
    && printf 'gantry ALL=(ALL:ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/gantry \
    && chmod 0440 /etc/sudoers.d/gantry \
    && visudo -cf /etc/sudoers.d/gantry

USER gantry
WORKDIR /home/gantry
ENV HOME=/home/gantry
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CMD ["/bin/bash"]
