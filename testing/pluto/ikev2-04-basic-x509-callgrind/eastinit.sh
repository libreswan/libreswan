/testing/guestbin/swan-prep --x509

../../guestbin/callgrind.sh /usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf --nofork > /tmp/$(hostname).pluto.calllog 2>&1 & sleep 1
../../guestbin/wait-until-pluto-started

ipsec add westnet-eastnet-ikev2
echo "initdone"
