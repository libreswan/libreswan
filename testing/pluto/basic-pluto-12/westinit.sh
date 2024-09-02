/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress_retransmits
ipsec auto --add westnet-eastnet
ipsec auto --add westnet-eastnet-7
ipsec auto --route westnet-eastnet-7
echo "initdone"
