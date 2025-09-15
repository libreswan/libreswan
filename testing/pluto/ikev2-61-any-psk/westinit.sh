/testing/guestbin/swan-prep --nokeys --46
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-east-psk
ipsec whack --impair suppress_retransmits
echo "initdone"
