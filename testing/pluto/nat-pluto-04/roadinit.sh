/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-nat
ipsec auto --status | grep road-eastnet-nat
echo "initdone"
