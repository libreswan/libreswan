/testing/guestbin/swan-prep
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-northnet-ipv4-psk
ipsec auto --status
echo "initdone"
