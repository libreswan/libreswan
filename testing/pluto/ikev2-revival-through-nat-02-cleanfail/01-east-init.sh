/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
# loaded via ipsec.conf - no ipsec auto --keep yet
echo "initdone"
