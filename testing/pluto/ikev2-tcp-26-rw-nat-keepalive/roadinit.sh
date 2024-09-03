/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add road
ipsec whack --impair suppress_retransmits
echo "initdone"
