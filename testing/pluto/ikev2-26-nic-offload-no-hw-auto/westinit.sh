/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-transport
ipsec whack --impair suppress-retransmits
echo "initdone"
