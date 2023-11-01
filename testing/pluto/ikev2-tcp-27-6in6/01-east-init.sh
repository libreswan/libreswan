/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add 6in6
echo "initdone"
