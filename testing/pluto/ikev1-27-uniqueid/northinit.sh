/testing/guestbin/swan-prep --x509
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-eastnet-ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"
