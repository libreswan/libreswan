/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/east.p12
/testing/x509/import.sh real/mainca/west.end.cert
# build install se module
../../guestbin/semodule.sh ipsecspd-full-perm.te
setenforce 0
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
echo "initdone"
