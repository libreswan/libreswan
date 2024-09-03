/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
ipsec whack --impair revival
