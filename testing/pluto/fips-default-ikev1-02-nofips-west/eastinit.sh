/testing/guestbin/swan-prep --fips --hostkeys
setenforce 0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
