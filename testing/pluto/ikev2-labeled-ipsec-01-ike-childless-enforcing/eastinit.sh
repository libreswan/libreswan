/testing/guestbin/swan-prep --hostkeys
# build install se module
../../guestbin/semodule.sh ipsecspd-full-perm.te
setenforce 1
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
echo "initdone"
