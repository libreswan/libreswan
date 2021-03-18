/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-foo
ipsec auto --add westnet-eastnet-bar
echo "initdone"
