/testing/guestbin/swan-prep --x509

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254

../../guestbin/callgrind.sh /usr/local/libexec/ipsec/pluto --config /etc/ipsec.conf --nofork > /tmp/$(hostname).pluto.calllog 2>&1 & sleep 1
../../guestbin/wait-until-pluto-started

ipsec add westnet-eastnet-ikev2
echo "initdone"
