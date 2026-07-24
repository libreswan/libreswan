/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/west.end.cert
ifconfig eth0:1 inet 192.0.2.244 netmask 255.255.255.0
ifconfig eth0:2 inet 192.0.2.234 netmask 255.255.255.0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add TUNNEL-A
ipsec auto --add TUNNEL-B
ipsec auto --add TUNNEL-C
echo "initdone"
