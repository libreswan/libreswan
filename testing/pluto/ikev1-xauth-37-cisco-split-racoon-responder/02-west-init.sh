/testing/guestbin/swan-prep
ipsec auto --start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east
ipsec whack --impair revival
echo "initdone"
