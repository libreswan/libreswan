/testing/guestbin/swan-prep --hostkeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair replay_inbound
ipsec add westnet-eastnet
echo "initdone"
