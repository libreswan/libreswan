/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add ikev1-east
ipsec add ikev2-east
echo initdone
