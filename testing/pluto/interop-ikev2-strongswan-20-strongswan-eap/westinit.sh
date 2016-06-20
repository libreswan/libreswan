/testing/guestbin/swan-prep --userland strongswan
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# make sure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
cp /testing/x509/certs/east.crt /etc/strongswan/ipsec.d/certs/
cp /testing/x509/cacerts/mainca.crt /etc/strongswan/ipsec.d/cacerts/
strongswan starter --debug-all
echo "initdone"
