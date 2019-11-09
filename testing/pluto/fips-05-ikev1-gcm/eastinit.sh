/testing/guestbin/swan-prep --fips
fipscheck
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-gcm
echo "initdone"
