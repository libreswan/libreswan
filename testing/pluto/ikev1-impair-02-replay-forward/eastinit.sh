/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair replay-forward
ipsec auto --add westnet-eastnet
echo "initdone"
