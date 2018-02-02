/testing/guestbin/swan-prep --userland strongswan --x509 --eccert
# strongswan expects the certs in /etc/strongswan/certs for some reason
mkdir -p /etc/strongswan/certs
cp -a /etc/strongswan/ipsec.d/certs/* /etc/strongswan/certs/
# confirm that the network is alive
../../pluto/bin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j LOGDROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm with a ping
ping -n -c 4 -I 192.0.1.254 192.0.2.254
../../pluto/bin/strongswan-start.sh
echo "initdone"
