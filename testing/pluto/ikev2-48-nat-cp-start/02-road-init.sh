/testing/guestbin/swan-prep
ip route
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
echo "initdone"
