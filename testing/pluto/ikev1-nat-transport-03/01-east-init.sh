/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add north-east-7
ipsec auto --add road-east-7
echo "initdone"
