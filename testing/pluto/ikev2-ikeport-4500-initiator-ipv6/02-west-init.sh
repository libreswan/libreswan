/testing/guestbin/swan-prep --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
ipsec whack --impair suppress_retransmits
echo "initdone"
