/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east-222
ipsec auto --add road-east-222
echo "initdone"
