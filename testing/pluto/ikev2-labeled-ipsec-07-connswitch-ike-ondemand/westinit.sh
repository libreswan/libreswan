/testing/guestbin/swan-prep --x509
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd-full-perm.pp
setenforce 0
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
#ipsec auto --add distraction
ipsec auto --add west-to-east
