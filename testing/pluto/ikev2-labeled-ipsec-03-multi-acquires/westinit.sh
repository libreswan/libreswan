/testing/guestbin/swan-prep
make -f /usr/share/selinux/devel/Makefile ipsecspd.pp 2> /dev/null
semodule -i ipsecspd.pp > /dev/null 2>/dev/null
rm ipsecspd.pp
ipsec start
../../guestbin/wait-until-pluto-started
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ipsec auto --add labeled
echo "initdone"
