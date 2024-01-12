/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec whack --impair replay_duplicates
ipsec auto --status
echo "initdone"
