/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet1
ipsec auto --add westnet-eastnet2
ipsec whack --impair suppress_retransmits
echo "initdone"
