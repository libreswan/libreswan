/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
echo "initdone"
ipsec whack --impair revival
