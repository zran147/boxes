set -eu
out=$(cat "/home/${BOX_U}/Documents/.backup")
echo "$out"
echo "$out" | grep -qx "$BOX_P" || { echo "steghide password not found" >&2; exit 1; }
