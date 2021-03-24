/testing/guestbin/swan-prep
make -f /usr/share/selinux/devel/Makefile ipsecspd.pp 2> /dev/null
semodule -i ipsecspd.pp > /dev/null 2>/dev/null
rm ipsecspd.pp
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
