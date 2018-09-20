# once unbound work properly replace the next lines
sed -i 's/5353/53/' /etc/nsd/nsd.conf
# /testing/guestbin/swan-prep --dnssec
systemctl start nsd-keygen
systemctl start nsd
dig +short @127.0.0.1  west.testing.libreswan.org
dig +short @127.0.0.1  east.testing.libreswan.org
echo done
: ==== end ====
