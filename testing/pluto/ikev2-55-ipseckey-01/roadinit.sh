/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add road-east-ikev2
ipsec whack --debug-all --impair retransmits
echo "initdone"
