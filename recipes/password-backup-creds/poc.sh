set -eu
out=$(cat /home/floris/password_backup)
echo "$out"
echo "$out" | grep -qx "$BOX_P" || { echo "backup password not found" >&2; exit 1; }
