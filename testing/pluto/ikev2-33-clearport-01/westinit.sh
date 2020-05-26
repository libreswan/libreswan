/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add pass-222
echo "initdone"
