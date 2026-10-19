set -eu
u="${BOX_U:?BOX_U is not set}"
p="${BOX_P:?BOX_P is not set}"
pkill -f 'server.py sqli 8087' 2>/dev/null || true
nohup env BOX_U="$u" BOX_P="$p" python3 "$BOX_ASSETS/server.py" sqli 8087 >/var/log/sqli.log 2>&1 &
sleep 1
