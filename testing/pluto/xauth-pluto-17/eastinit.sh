/testing/guestbin/swan-prep
ipsec _stackmanager start 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add xauth-road--eastnet-psk
ipsec auto --status
echo "initdone"
