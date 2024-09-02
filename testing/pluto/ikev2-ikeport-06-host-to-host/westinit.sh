/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west-east-ikev2
ipsec auto --status | grep west-east-ikev2
ipsec whack --impair suppress_retransmits
echo "initdone"
