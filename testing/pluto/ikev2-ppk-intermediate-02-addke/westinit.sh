/testing/guestbin/swan-prep --nokeys

ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair revival
echo "initdone"
