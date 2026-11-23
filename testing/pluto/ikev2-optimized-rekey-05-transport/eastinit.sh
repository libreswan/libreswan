/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add transport-optimized-rekey
ipsec connectionstatus transport-optimized-rekey
echo "initdone"
