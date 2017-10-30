iptables -t nat -F
iptables -F
iptables -X
../bin/block-non-ipsec.sh
echo done
: ==== end ====
