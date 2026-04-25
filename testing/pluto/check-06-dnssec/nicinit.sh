iptables -t nat -F
iptables -F
/bin/time -o OUTPUT/$(hostname).time /testing/guestbin/start-dns.sh
echo done
