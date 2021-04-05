/testing/guestbin/swan-prep --fips
ipsec checknss
/u../../guestbin/modutil -dbdir sql:/etc/ipsec.d -fips true -force
/u../../guestbin/modutil -dbdir sql:/etc/ipsec.d -chkfips true
fipscheck
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-md5
echo "initdone"
