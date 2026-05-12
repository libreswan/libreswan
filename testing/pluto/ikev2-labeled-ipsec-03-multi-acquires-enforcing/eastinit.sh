/testing/guestbin/swan-prep --hostkeys
# build install se module
../../guestbin/semodule.sh ipsecspd.te
# cheat that might not work? start before enabling selinux
ipsec _getpeercon_server -d 4300
setenforce 1
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec add labeled
echo "initdone"
