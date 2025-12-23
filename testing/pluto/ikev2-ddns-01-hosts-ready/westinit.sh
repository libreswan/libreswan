/testing/guestbin/swan-prep --nokeys

../../guestbin/mount-bind.sh /etc/hosts /etc/hosts
grep right.libreswan.org /etc/hosts && echo "TEST FAILED - should not have /etc/hosts entry at start" || true
echo "192.1.2.23 right.libreswan.org" >> /etc/hosts

ipsec start
../../guestbin/wait-until-pluto-started
