/testing/guestbin/swan-prep --nokeys
../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
if grep right.libreswan.org /etc/hosts ; then echo "TEST FAILED - should not have /etc/hosts entry at start" ; false ; else : ; fi
ipsec start
../../guestbin/wait-until-pluto-started
# will be slow because of the right dns name resolution failing
echo "initdone"
