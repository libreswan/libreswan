iptables -t nat -F
iptables -F
setenforce Permissive
/testing/guestbin/nic-dnssec.sh start
echo "initdone"
: ==== end ====
