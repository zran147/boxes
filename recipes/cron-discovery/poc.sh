set -eu
test -w /opt/boxes-cron/run.sh || { echo "cron script is not writable" >&2; exit 1; }
echo "writable cron script: /opt/boxes-cron/run.sh"
