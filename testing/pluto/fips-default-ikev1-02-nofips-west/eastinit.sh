/testing/guestbin/swan-prep --fips
fipscheck
setenforce 0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
