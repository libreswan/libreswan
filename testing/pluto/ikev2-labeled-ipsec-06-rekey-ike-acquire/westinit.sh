/testing/guestbin/swan-prep --hostkeys
echo 3 > /proc/sys/net/core/xfrm_acq_expires
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd-full-perm.pp
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
