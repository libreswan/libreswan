/testing/guestbin/swan-prep --nokeys --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add any-east
echo "initdone"
