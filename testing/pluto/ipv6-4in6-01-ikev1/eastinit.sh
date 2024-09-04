/testing/guestbin/swan-prep --46 --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-4in6
echo "initdone"
