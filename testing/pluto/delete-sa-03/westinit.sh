/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east
ipsec auto --add west-east-b
ipsec auto --add west-east-c
ipsec auto --status | grep west-
ipsec whack --impair suppress_retransmits
echo "initdone"
