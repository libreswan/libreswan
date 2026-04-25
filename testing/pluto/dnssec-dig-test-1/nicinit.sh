iptables -t nat -F
iptables -F
time /testing/guestbin/start-dns.sh
echo done
