/testing/guestbin/swan-prep --x509
#add address from to be extruded subnet on road.
ifconfig eth0:1 192.0.1.254/24
# confirm that the network is alive
../../pluto/bin/wait-until-alive 192.0.2.254
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-ikev2
ipsec auto --status | grep road-east-ipv4-ikev2
echo "initdone"
