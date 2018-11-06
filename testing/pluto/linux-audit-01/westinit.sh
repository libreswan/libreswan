/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add ikev1
ipsec auto --add ikev1-aggr
ipsec auto --add ikev2
ipsec whack --impair suppress-retransmits
echo "initdone"
