/testing/guestbin/swan-prep --x509
ipsec setup start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-ikev2
echo "initdone"
