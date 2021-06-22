/testing/guestbin/swan-prep
make -f /usr/share/selinux/devel/Makefile ipsecspd.pp 2> /dev/null
# build install se module
../../guestbin/semodule.sh ipsecspd.te
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
