/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet-nonat
ipsec auto --status
echo "initdone"
