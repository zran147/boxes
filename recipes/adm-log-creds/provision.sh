set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
mkdir -p /var/log/audit
printf 'user=shaun password=%s\n' "$p" > /var/log/audit/audit.log
chmod 0644 /var/log/audit/audit.log
