/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-transport
ipsec whack --impair suppress_retransmits
echo "initdone"
# expected to fail
ipsec auto --up west-east-transport
