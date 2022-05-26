/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add 6in6
echo "initdone"
