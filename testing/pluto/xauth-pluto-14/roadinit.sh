/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add modecfg-road-east
ipsec whack --impair suppress_retransmits
echo "initdone"
