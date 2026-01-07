/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started
echo "initdone"
cp /usr/share/crypto-policies/back-ends/DEFAULT/libreswan.config /tmp/west-add.conf
ipsec auto --add test
ipsec status | grep algorithms: # DEFAULT
rm /tmp/west-add.conf
#
cp /usr/share/crypto-policies/back-ends/FIPS/libreswan.config /tmp/west-add.conf
ipsec auto --add test
ipsec status | grep algorithms: # FIPS
rm /tmp/west-add.conf
#
cp /usr/share/crypto-policies/back-ends/FUTURE/libreswan.config /tmp/west-add.conf
ipsec auto --add test
ipsec status | grep algorithms: # FUTURE
rm /tmp/west-add.conf
#
cp /usr/share/crypto-policies/back-ends/LEGACY/libreswan.config /tmp/west-add.conf
ipsec auto --add test
ipsec status | grep algorithms: # LEGACY
rm /tmp/west-add.conf
