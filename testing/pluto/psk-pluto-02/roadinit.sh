/testing/guestbin/swan-prep 
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-psk
ipsec auto --status
echo "initdone"
