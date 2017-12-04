/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-dh19
ipsec auto --status | grep westnet-eastnet-dh19
echo "initdone"
