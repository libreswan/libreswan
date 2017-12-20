/testing/guestbin/swan-prep --dnssec
systemctl restart nsd
: ==== cut ====
dig +short @127.0.0.1 north.testing.libreswan.org IPSECKEY
dig +short @127.0.0.1 east.testing.libreswan.org IPSECKEY
dig +short @192.1.2.254 chaos version.server txt
: ==== tuc ====
echo done
: ==== end ====
