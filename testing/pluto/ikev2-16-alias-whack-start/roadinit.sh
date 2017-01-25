/testing/guestbin/swan-prep --x509
#add address from to be extruded subnet on road.
ifconfig eth0:1 192.0.1.254/24
ifconfig eth0:11 192.0.11.254/24
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-psk-ikev2
echo "initdone"
