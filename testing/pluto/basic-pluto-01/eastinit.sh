/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec auto --status
echo "initdone"
