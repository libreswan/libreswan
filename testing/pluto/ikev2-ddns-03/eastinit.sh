/testing/guestbin/swan-prep
# not really used in this test
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add named
echo "initdone"
