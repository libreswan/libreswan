/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-northnet-ipv4-psk
ipsec auto --add northnet-westnet-ipv4-psk
ipsec auto --status
echo "initdone"
