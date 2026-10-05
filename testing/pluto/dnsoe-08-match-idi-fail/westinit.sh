/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec whack --impair revival
ipsec add west-east
echo "initdone"
