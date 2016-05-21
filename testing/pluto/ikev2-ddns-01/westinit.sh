/testing/guestbin/swan-prep
grep right.libreswan.org /etc/hosts > /dev/null && echo "TEST FAILED - should not have /etc/hosts entry at start"
ipsec start
/testing/pluto/bin/wait-until-pluto-started
# will throw an error about bad unresolvable name
ipsec auto --add named
echo "initdone"
