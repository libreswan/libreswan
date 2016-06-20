/testing/guestbin/swan-prep --46
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add v6-transport
echo "initdone"
