/testing/guestbin/swan-prep
../../guestbin/ip-route.sh
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
echo "initdone"
