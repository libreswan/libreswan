#once unbound work properly replace the next lines
sed -i 's/5353/53/' /etc/nsd/nsd.conf
#/testing/guestbin/swan-prep --dnssec
setenforce 0
systemctl start nsd-keygen
systemctl start nsd
dig +short  @127.0.0.1  road.testing.libreswan.org  IPSECKEY
: ==== cut ====
dig +short @192.1.2.254 chaos version.server txt
: ==== tuc ====
echo done
: ==== end ====
