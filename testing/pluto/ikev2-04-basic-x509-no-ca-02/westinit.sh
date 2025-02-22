/testing/guestbin/swan-prep --nokeys

# only the end, both ends hardcode certs
ipsec pk12util -W foobar -K '' -i /testing/x509/real/mainca/west.end.p12
/testing/x509/import.sh real/mainca/east.end.cert
# load a distraction CA and Cert
ipsec pk12util -W foobar -K '' -i /testing/x509/real/otherca/otherwest.all.p12
# check result
ipsec certutil -L

# confirm that the network is alive
../../guestbin/wait-until-alive -I 192.0.1.254 192.0.2.254
# ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
# confirm clear text does not get through
../../guestbin/ping-once.sh --down -I 192.0.1.254 192.0.2.254

ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
ipsec auto --status | grep westnet-eastnet-ikev2
echo "initdone"
