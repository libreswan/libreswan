/testing/guestbin/swan-prep
setenforce 1
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add ikev1
ipsec auto --add ikev1-aggr
ipsec auto --add ikev2
echo "initdone"
