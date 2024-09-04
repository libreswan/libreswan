ip route delete default via 10.1.2.11 dev eth2
/testing/guestbin/swan-prep
ipsec start
ip route add  192.1.8.0/24 via 192.1.2.254 2>&1 > /dev/null
../../guestbin/wait-until-pluto-started
ipsec auto --add eastnet-northnet
echo "initdone"
