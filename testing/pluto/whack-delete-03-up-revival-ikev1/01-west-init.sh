/testing/guestbin/swan-prep --46 --nokey
ipsec start
../../guestbin/wait-until-pluto-started

ipsec whack --impair revival
ipsec whack --impair timeout_on_retransmit
ipsec add west

echo "initdone"
