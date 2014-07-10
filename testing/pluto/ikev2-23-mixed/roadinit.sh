/testing/guestbin/swan-prep --x509
#add address from to be extruded subnet on road.
ifconfig eth0:1 192.0.1.254/24
ifconfig eth0:2 192.0.11.254/24
# confirm that the network is alive
ping -n -c 4 192.0.2.254
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-ikev2
ipsec auto --add road-east-ipv4
ipsec auto --status
echo "initdone"
