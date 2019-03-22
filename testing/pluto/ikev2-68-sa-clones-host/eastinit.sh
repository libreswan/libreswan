/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --status | grep west-east
ipsec whack --impair suppress-retransmits
echo "initdone"
