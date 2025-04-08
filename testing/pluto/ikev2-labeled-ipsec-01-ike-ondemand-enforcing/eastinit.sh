/testing/guestbin/swan-prep
# build install se module
../../guestbin/semodule.sh ipsecspd-full-perm.te
setenforce 1
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
