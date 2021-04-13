/testing/guestbin/swan-prep
grep right.libreswan.org /etc/hosts > /dev/null && echo "TEST FAILED - should not have /etc/hosts entry at start"
ipsec start
../../guestbin/wait-until-pluto-started
# will be slow because of the right dns name resolution failing
echo "initdone"
