/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-null
ipsec auto --status | grep westnet-eastnet-null
echo "initdone"
