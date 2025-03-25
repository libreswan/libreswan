/testing/guestbin/swan-prep --userland strongswan

cp /testing/x509/real/mainca/root.cert /etc/strongswan/ipsec.d/cacerts/mainca.crt
cp /testing/x509/real/mainca/`hostname`.key /etc/strongswan/ipsec.d/private/`hostname`.key
cp /testing/x509/real/mainca/`hostname`.end.cert /etc/strongswan/ipsec.d/certs/`hostname`.crt
# why?
cp /testing/x509/real/mainca/east.end.cert /etc/strongswan/ipsec.d/certs/east.crt

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254
setenforce 0
../../guestbin/strongswan-start.sh
echo "initdone"
