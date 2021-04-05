/testing/guestbin/swan-prep
# ensure that clear text does not get through
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --status
echo "initdone"
