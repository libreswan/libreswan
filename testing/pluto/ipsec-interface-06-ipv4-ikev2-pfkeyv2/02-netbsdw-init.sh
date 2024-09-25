/testing/guestbin/netbsd-prep.sh
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west
echo "initdone"
