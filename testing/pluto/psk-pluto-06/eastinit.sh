/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-psk
ipsec auto --add road-east-psk
ipsec auto --add xauth-road-eastnet-psk
echo "initdone"
