/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-sha2
ipsec auto --status | grep westnet-eastnet-sha2
echo "initdone"
