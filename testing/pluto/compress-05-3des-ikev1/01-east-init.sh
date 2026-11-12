/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add westnet-eastnet-esp-3des-alg
ipsec connectionstatus westnet-eastnet-esp-3des-alg
echo "initdone"
