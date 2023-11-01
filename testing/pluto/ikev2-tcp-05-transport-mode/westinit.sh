/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add ikev2-west-east
echo "initdone"
