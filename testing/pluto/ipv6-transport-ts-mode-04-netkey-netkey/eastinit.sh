/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add v6-transport
../../guestbin/echod.sh -6 1701
echo "initdone"
