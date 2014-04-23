/testing/guestbin/swan-prep
ipsec _stackmanager start 
ipsec setup start:
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-nonat
ipsec auto --status
echo "initdone"
