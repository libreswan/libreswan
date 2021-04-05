/testing/guestbin/swan-prep
# not really used in this test
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add named
echo "initdone"
