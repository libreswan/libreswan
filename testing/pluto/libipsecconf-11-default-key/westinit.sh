/testing/guestbin/swan-prep
ip addr add 192.1.2.46/24 dev eth1
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
