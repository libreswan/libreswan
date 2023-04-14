iptables -t nat -F
iptables -F
iptables -X
../../guestbin/block-non-ipsec.sh
echo done
: ==== end ====
