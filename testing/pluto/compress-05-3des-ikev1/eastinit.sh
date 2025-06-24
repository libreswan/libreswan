/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-esp-3des-alg
ipsec auto --status | grep westnet-eastnet-esp-3des-alg
echo "initdone"
