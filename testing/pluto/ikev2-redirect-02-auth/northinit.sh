/testing/guestbin/swan-prep
ifconfig eth0:1 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add any-northnet-ipv4-psk-ikev2
echo "initdone"
