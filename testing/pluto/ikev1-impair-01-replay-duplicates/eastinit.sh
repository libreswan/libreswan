/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair replay-duplicates
ipsec auto --add westnet-eastnet
ipsec auto --status
echo "initdone"
