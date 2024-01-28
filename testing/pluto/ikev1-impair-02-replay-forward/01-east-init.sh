/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair replay_inbound
ipsec auto --add westnet-eastnet
echo "initdone"
