# Package/artifact proxy for provisioning.
#
# - apt-cacher-ng on 3142: durable apt cache (pinned snapshots too)
# - squid on 3128: general HTTP/HTTPS (pip, curl), memory cache
# - static artifact server on 8000
# Only this container has egress; targets reach it on the provisioning network.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        apt-cacher-ng \
        squid \
        python3 \
        ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/cache/apt-cacher-ng /var/spool/squid /srv/artifacts \
 && chown -R apt-cacher-ng:apt-cacher-ng /var/cache/apt-cacher-ng \
 && for d in $(seq 0 15); do mkdir -p "/var/spool/squid/$(printf '%02X' "$d")"; done \
 && chown -R proxy:proxy /var/spool/squid

COPY squid.conf /etc/squid/squid.conf
COPY start.sh /usr/local/bin/start.sh
RUN chmod 0755 /usr/local/bin/start.sh

EXPOSE 3128 3142 8000

CMD ["/usr/local/bin/start.sh"]
