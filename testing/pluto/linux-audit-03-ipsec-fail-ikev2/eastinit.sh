/testing/guestbin/swan-prep --hostkeys
setenforce 1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev2
echo "initdone"
