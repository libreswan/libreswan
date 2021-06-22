/testing/guestbin/swan-prep
# build install se module
../../guestbin/semodule.sh ipsecspd.te
setenforce 1
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ipsec auto --add labeled
runcon -t netutils_t ipsec getpeercon_server 4300 &
echo "initdone"
