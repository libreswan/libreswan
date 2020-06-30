ln -s /usr/share/crypto-policies/back-ends/DEFAULT/libreswan.config OUTPUT/west-add.conf
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add test
ipsec status | grep algorithms:
rm OUTPUT/west-add.conf
#
ln -s /usr/share/crypto-policies/back-ends/FIPS/libreswan.config OUTPUT/west-add.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add test
ipsec status | grep algorithms:
rm OUTPUT/west-add.conf
#
ln -s /usr/share/crypto-policies/back-ends/FUTURE/libreswan.config OUTPUT/west-add.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add test
ipsec status | grep algorithms:
rm OUTPUT/west-add.conf
#
ln -s /usr/share/crypto-policies/back-ends/LEGACY/libreswan.config OUTPUT/west-add.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add test
ipsec status | grep algorithms:
rm OUTPUT/west-add.conf
#
ln -s /usr/share/crypto-policies/back-ends/NEXT/libreswan.config OUTPUT/west-add.conf
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add test
ipsec status | grep algorithms:
rm OUTPUT/west-add.conf
echo done
