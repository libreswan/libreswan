/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add northnet-westnet-ipv4-psk
ipsec auto --status
echo "initdone"
