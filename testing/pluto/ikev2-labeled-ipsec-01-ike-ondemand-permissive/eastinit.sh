/testing/guestbin/swan-prep --hostkeys
# build install se module
../../guestbin/semodule.sh ipsecspd-full-perm.te
setenforce 0
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
