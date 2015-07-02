/testing/guestbin/swan-prep --fips
ipsec checknss
/usr/bin/modutil -dbdir sql:/etc/ipsec.d -fips true -force
/usr/bin/modutil -dbdir sql:/etc/ipsec.d -chkfips true
fipscheck
ipsec start
/testing/pluto/bin/wait-until-pluto-started
grep FIPS /tmp/pluto.log
ipsec auto --add westnet-eastnet-md5
echo "initdone"
