/testing/guestbin/swan-prep --x509
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east-x509-ipv4
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
echo "initdone"
