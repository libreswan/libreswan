/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
ipsec whack --impair replay-duplicates
ipsec auto --status
echo "initdone"
