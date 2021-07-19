/testing/guestbin/swan-prep
# build install se module
../../guestbin/semodule.sh ipsecspd.te
# cheat that might not work? start before enabling selinux
ipsec getpeercon_server 4300 &
setenforce 1
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ipsec auto --add labeled
echo "initdone"
