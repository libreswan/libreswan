setenforce Permissive
/testing/guestbin/dnssec.sh
dig +short  @127.0.0.1  road.testing.libreswan.org  IPSECKEY | sort
: ==== cut ====
dig +short @192.1.2.254 chaos version.server txt
: ==== tuc ====
echo done
: ==== end ====
