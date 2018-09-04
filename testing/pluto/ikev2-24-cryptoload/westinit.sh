/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add multi
#ipsec whack --impair suppress-retransmits
echo "initdone"
