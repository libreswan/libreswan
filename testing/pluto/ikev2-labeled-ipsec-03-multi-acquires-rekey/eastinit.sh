/testing/guestbin/swan-prep
# build install se module
../../guestbin/semodule.sh ipsecspd.te
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ipsec auto --add labeled
ipsec getpeercon_server 4300 &
echo "initdone"
