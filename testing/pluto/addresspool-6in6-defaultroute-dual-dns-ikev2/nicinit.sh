iptables -t nat -F
iptables -F
setenforce Permissive
/testing/guestbin/swan-prep --dnssec
dig +short  @127.0.0.1 road.testing.libreswan.org
dig +short  @127.0.0.1 east.testing.libreswan.org
: ==== cut ====
dig +short @192.1.2.254 chaos version.server txt
: ==== tuc ====
echo "initdone"
: ==== end ====
