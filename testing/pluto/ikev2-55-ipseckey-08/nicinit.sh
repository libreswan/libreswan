/testing/guestbin/swan-prep --dnssec
: ==== cut ====
systemctl start nsd-keygen
/usr/sbin/nsd > /dev/null 2> /dev/null
dig +short @127.0.0.1 33.3.1.192.IN-ADDR.ARPA. IPSECKEY
dig +short @127.0.0.1 23.2.1.192.IN-ADDR.ARPA. IPSECKEY
dig +short @192.1.2.254 chaos version.server txt
echo done
: ==== end ====
