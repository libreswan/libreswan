/testing/guestbin/swan-prep --46 --nokey
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add west # alias; includes west-base, oops!
ipsec delete west-base

echo "initdone"
