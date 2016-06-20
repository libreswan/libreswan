/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-dh15
ipsec auto --status | grep westnet-eastnet-dh15
echo "initdone"
