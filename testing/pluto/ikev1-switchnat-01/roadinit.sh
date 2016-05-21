/testing/guestbin/swan-prep --x509
ip addr add 192.1.3.208/24 dev eth0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
echo "initdone"
