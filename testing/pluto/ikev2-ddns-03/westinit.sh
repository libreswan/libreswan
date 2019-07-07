/testing/guestbin/swan-prep
grep right.libreswan.org /etc/hosts > /dev/null && echo "TEST FAILED - should not have /etc/hosts entry at start"
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add named
ipsec status | grep "===" # should show %dns for pending resolve
echo "initdone"
