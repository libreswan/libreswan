/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-east-sourceip
ipsec whack --impair suppress-retransmits
echo "initdone"
