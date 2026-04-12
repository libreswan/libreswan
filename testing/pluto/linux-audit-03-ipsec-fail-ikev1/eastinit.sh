/testing/guestbin/swan-prep --hostkeys
setenforce 1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add ikev1
ipsec add ikev1-aggr
echo "initdone"
