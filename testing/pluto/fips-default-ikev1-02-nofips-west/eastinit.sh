/testing/guestbin/swan-prep --hostkeys
/testing/guestbin/fips.sh on
setenforce 0
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
