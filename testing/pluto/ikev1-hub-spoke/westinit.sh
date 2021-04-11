/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-northnet-ipv4-psk
ipsec auto --status
echo "initdone"
