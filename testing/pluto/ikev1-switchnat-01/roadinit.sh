/testing/guestbin/swan-prep --x509
ip addr add 192.1.3.208/24 dev eth0
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road1
ipsec auto --add road2
echo "initdone"
