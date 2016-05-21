/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-passthrough
ipsec auto --route westnet-eastnet-passthrough
ipsec auto --add westnet-eastnet
echo "initdone"
