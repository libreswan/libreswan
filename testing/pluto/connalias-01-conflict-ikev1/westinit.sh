/testing/guestbin/swan-prep --hostkeys

ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair revival

ipsec add westnet-eastnet-alias
ipsec add westnet-eastnet-second
ipsec connectionstatus westnet-eastnet
echo "initdone"
