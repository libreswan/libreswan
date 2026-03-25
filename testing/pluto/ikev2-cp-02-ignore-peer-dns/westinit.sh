/testing/guestbin/swan-prep --nokeys
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add west-eastnet
# confirm we have stock resolv.conf
cat /etc/resolv.conf
echo initdone
