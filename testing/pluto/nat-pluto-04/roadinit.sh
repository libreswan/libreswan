/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet-nat
ipsec auto --status | grep road-eastnet-nat
ipsec whack --impair suppress-retransmits
echo "initdone"
