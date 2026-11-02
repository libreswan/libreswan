/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add transport-optimized-rekey
ipsec auto --status | grep transport-optimized-rekey
echo "initdone"
