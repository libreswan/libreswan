/testing/guestbin/swan-prep --46 --x509
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-psk-ikev2
ipsec auto --add road-east-ipv6-psk-ikev2
ipsec auto --status
echo "initdone"
