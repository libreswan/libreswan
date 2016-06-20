/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-compress
ipsec auto --status | grep westnet-eastnet-compress
echo "initdone"
