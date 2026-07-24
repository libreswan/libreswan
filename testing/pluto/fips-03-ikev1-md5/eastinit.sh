/testing/guestbin/swan-prep --nokeys
/testing/guestbin/fips.sh on
ipsec checknss
modutil -dbdir sql:/etc/ipsec.d -fips true -force
modutil -dbdir sql:/etc/ipsec.d -chkfips true
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add westnet-eastnet-md5
echo "initdone"
