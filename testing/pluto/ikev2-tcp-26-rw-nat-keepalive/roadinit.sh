/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road
ipsec whack --impair suppress-retransmits
echo "initdone"
