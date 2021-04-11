/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east
../../guestbin/tcpdump.sh --start -i eth1
echo "initdone"
