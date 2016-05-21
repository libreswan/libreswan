/testing/guestbin/swan-prep
# make sure that clear text does not get through
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --status
echo "initdone"
