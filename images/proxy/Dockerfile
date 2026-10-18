# Package/artifact proxy for provisioning.
#
# Squid handles apt over HTTP and pip/other HTTPS via CONNECT, with a cache and
# a domain allowlist. A small static file server exposes the artifact store.
# The targets never get direct internet.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        squid \
        python3 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/spool/squid /srv/artifacts \
 && for d in $(seq 0 15); do mkdir -p "/var/spool/squid/$(printf '%02X' "$d")"; done \
 && chown -R proxy:proxy /var/spool/squid

COPY squid.conf /etc/squid/squid.conf
COPY start.sh /usr/local/bin/start.sh
RUN chmod 0755 /usr/local/bin/start.sh

EXPOSE 3128 8000

CMD ["/usr/local/bin/start.sh"]
