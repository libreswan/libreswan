/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival
ipsec auto --add westnet-eastnet-aggr
echo "initdone"
