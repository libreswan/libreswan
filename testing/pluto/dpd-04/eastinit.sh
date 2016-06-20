/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add west-eastnet
ipsec auto --add westnet-east
echo "initdone"
