iptables -t nat -F
iptables -F
setenforce Permissive
/testing/guestbin/start-dns.sh
echo "initdone"
: ==== end ====
