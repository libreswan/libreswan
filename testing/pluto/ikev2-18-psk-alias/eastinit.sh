/testing/guestbin/swan-prep --46
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add roadnet-eastnet-ipv4-psk-ikev2
ipsec auto --add roadnet-eastnet-ipv6-psk-ikev2
ipsec auto --status
echo "initdone"
