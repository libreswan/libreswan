/testing/guestbin/swan-prep
echo 3 > /proc/sys/net/core/xfrm_acq_expires
# build install se module (west only)
../../guestbin/semodule.sh ipsecspd-full-perm.te
# start pluto
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
