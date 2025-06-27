/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec add west-east
echo "initdone"
