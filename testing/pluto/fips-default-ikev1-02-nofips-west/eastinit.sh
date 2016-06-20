/testing/guestbin/swan-prep --fips
/usr/bin/modutil -dbdir /etc/ipsec.d -fips true -force
/usr/bin/modutil -dbdir /etc/ipsec.d -chkfips true
fipscheck
setenforce 0
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add westnet-eastnet
echo "initdone"
