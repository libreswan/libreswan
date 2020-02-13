# once unbound work properly replace the next lines
#/testing/guestbin/swan-prep --dnssec
# sed -i 's/5353/53/' /etc/nsd/nsd.conf
setenforce Permissive
/testing/guestbin/swan-prep --nsd
systemctl start nsd-keygen
/usr/sbin/nsd > /dev/null 2> /dev/null
dig +short  @127.0.0.1  road.testing.libreswan.org  IPSECKEY
: ==== cut ====
dig +short @192.1.2.254 chaos version.server txt
: ==== tuc ====
echo done
: ==== end ====
