/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add float-east
ipsec auto --add west-float
echo "initdone"
