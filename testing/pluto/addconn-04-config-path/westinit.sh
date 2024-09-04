/testing/guestbin/swan-prep --nokeys
cp test.conf /tmp/test.conf
ipsec pluto --config /tmp/test.conf
../../guestbin/wait-until-pluto-started
echo "initdone"
