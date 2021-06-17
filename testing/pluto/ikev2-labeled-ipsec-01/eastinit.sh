/testing/guestbin/swan-prep
echo 3 > /proc/sys/net/core/xfrm_acq_expires
# generate in OUTPUT directory
( cd OUTPUT && rm -f ipsecspd.pp ipsecspd.te )
( cd OUTPUT && ln -s ../ipsecspd.te )
( cd OUTPUT && make -f /usr/share/selinux/devel/Makefile ipsecspd.pp )
( cd OUTPUT && semodule -i ipsecspd.pp )
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
ipsec getpeercon_server 4300 &
echo "initdone"
