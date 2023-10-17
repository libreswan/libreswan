/testing/guestbin/swan-prep
../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
if grep right.libreswan.org /etc/hosts ; then echo "TEST FAILED - should not have /etc/hosts entry at start" ; false ; else : ; fi
ipsec start
../../guestbin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits
ipsec auto --add named
ipsec status | grep "===" # should show %dns for pending resolve
echo "initdone"
