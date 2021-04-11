/testing/guestbin/swan-prep
grep right.libreswan.org /etc/hosts > /dev/null && echo "TEST FAILED - should not have /etc/hosts entry at start"
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add named
ipsec status | grep "===" # should show %dns for pending resolve
echo "initdone"
