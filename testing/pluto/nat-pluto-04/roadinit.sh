/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add road-eastnet-nat
ipsec auto --status | grep road-eastnet-nat
ipsec whack --impair suppress_retransmits
echo "initdone"
