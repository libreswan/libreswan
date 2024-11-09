/testing/guestbin/swan-prep --46 --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add v6-transport
ipsec auto --status
echo "initdone"
