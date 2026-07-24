/testing/guestbin/swan-prep --nokeys
/testing/guestbin/fips.sh on
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-md5
echo "initdone"
