/testing/guestbin/swan-prep
ipsec _stackmanager start 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-esp-null-alg
ipsec auto --status
echo "initdone"
