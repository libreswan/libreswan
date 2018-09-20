/testing/guestbin/swan-prep --fips
fipscheck
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-ikev2
echo "initdone"
