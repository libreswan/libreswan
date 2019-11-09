/testing/guestbin/swan-prep
cp test.conf /tmp/test.conf
ipsec pluto --config /tmp/test.conf
/testing/pluto/bin/wait-until-pluto-started
echo "initdone"
