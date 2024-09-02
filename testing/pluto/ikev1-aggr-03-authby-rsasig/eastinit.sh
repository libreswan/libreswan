/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-aggr
ipsec auto --status | grep westnet-eastnet-aggr
echo "initdone"
