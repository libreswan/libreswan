/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet-nat
echo "initdone"
