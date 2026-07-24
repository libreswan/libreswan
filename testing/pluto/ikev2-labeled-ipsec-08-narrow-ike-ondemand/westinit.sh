/testing/guestbin/swan-prep --nokeys
/testing/x509/import.sh real/mainca/west.p12
/testing/x509/import.sh real/mainca/east.end.cert
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd-full-perm.pp
setenforce 0
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
echo "initdone"
