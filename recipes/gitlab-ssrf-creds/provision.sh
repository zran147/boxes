set -eu
mkdir -p /srv/gitlab
printf 'GITLAB_USER=dexter\nGITLAB_PASS=%s\n' "${BOX_P:-password}" > /srv/gitlab/creds.txt
pkill -f 'http.server 8095' 2>/dev/null || true
nohup python3 -m http.server 8095 --directory /srv/gitlab >/var/log/gitlab.log 2>&1 &
sleep 1
