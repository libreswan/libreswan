/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair suppress-retransmits
ipsec auto --add west-east
sleep 4
echo "initdone"
