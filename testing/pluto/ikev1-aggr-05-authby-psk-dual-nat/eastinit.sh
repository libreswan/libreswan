/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road-east
ipsec add runner-east
echo "initdone"
