/testing/guestbin/prep.sh

ipsec start
../../guestbin/wait-until-pluto-started

ipsec add elvis
ipsec up elvis
