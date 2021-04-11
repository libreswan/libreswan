/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add modecfg-road-east
ipsec whack --impair suppress-retransmits
echo "initdone"
