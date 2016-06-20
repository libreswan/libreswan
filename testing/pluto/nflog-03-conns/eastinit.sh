/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-nflog
ipsec auto --add west-east-nflog
echo "initdone"
