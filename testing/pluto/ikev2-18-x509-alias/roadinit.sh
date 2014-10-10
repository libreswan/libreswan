/testing/guestbin/swan-prep --46 --x509
#add address from to be extruded subnet on road.
ifconfig eth0:1 192.0.1.254/24
ifconfig eth0:11 192.0.11.254/24
# confirm that the network is alive
ping6 -n -c 4 2001:db8:1:2::23
ping -n -c 4 -I 192.0.1.254 192.0.2.254
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-psk-ikev2
ipsec auto --add road-east-ipv6-psk-ikev2
ipsec auto --status
echo "initdone"
