/testing/guestbin/swan-prep --userland strongswan
strongswan starter --debug-all
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-ikev2
echo "initdone"
