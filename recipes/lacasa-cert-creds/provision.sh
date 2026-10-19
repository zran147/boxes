set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
mkdir -p /home/professor
printf 'SSH_USER=professor\nSSH_PASS=%s\n' "$p" > /home/professor/creds.txt
chmod 0644 /home/professor/creds.txt
