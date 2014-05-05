/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add west-eastnet
ipsec auto --add westnet-east
/testing/pluto/bin/wait-until-policy-loaded
echo "initdone"
