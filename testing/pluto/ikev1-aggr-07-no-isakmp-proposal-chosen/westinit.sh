/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-aggr
ipsec whack --impair timeout_on_retransmit
echo "initdone"
