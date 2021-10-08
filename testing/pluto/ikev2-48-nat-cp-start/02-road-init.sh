/testing/guestbin/swan-prep
ip route
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
echo "initdone"
