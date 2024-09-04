/testing/guestbin/swan-prep --46  --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-6in4
echo "initdone"
