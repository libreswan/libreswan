/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
echo "initdone"
