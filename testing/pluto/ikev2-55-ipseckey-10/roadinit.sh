/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-east
ipsec whack --impair suppress_retransmits
echo "initdone"
