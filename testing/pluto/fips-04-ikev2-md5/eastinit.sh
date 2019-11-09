/testing/guestbin/swan-prep --fips
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-md5
echo "initdone"
