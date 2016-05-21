/testing/guestbin/swan-prep --x509
ifconfig eth0:1 inet 192.0.2.244 netmask 255.255.255.0
ifconfig eth0:2 inet 192.0.2.234 netmask 255.255.255.0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add TUNNEL-A
ipsec auto --add TUNNEL-B
ipsec auto --add TUNNEL-C
echo "initdone"
