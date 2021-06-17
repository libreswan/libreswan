/testing/guestbin/swan-prep
echo 3 > /proc/sys/net/core/xfrm_acq_expires
# generate in output directory
rm -f OUTPUT/ipsecspd.pp OUTPUT/ipsecspd.te
ln -s ../ipsecspd.te OUTPUT
make -C OUTPUT/ -f /usr/share/selinux/devel/Makefile ipsecspd.pp >/dev/null 2>/dev/null
semodule -i OUTPUT/ipsecspd.pp > /dev/null 2>/dev/null
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
