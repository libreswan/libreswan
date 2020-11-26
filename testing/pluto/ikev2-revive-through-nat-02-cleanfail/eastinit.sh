/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# loaded via ipsec.conf - no ipsec auto --keep yet
echo "initdone"
