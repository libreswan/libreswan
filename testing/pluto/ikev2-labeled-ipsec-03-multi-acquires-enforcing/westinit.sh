/testing/guestbin/swan-prep
# install selinux; generated in OUTPUT by east
semodule -i OUTPUT/ipsecspd.pp
setenforce 1
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ipsec auto --add labeled
echo "initdone"
