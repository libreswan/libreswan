ln -s /usr/share/crypto-policies/back-ends/DEFAULT/libreswan.config OUTPUT/west-add.conf
ipsec auto --add test
ipsec status | grep algorithms: # DEFAULT
rm OUTPUT/west-add.conf
#
ln -s /usr/share/crypto-policies/back-ends/FIPS/libreswan.config OUTPUT/west-add.conf
ipsec auto --add test
ipsec status | grep algorithms: # FIPS
rm OUTPUT/west-add.conf
#
ln -s /usr/share/crypto-policies/back-ends/FUTURE/libreswan.config OUTPUT/west-add.conf
ipsec auto --add test
ipsec status | grep algorithms: # FUTURE
rm OUTPUT/west-add.conf
#
ln -s /usr/share/crypto-policies/back-ends/LEGACY/libreswan.config OUTPUT/west-add.conf
ipsec auto --add test
ipsec status | grep algorithms: # LEGACY
rm OUTPUT/west-add.conf
