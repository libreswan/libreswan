/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet
ipsec status | grep encapsulation:
echo "initdone"
