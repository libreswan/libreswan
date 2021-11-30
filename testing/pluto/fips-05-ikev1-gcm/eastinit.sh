/testing/guestbin/swan-prep --fips
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-gcm
echo "initdone"
