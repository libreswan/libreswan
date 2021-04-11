/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add northnet-eastnet
ipsec whack --impair suppress-retransmits
echo "initdone"
