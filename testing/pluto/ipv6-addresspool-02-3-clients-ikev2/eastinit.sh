/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
ipsec auto --status | grep east
echo "initdone"
