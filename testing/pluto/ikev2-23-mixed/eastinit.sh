/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-ipv4-ikev2
ipsec auto --add road-east-ipv4
echo "initdone"
