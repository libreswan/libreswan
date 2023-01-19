/testing/guestbin/swan-prep
cp test.conf /tmp/test.conf
ipsec pluto --config /tmp/test.conf
../../guestbin/wait-until-pluto-started
echo "initdone"
