/testing/guestbin/swan-prep --hostkeys
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd-full-perm.pp
setenforce 0
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
