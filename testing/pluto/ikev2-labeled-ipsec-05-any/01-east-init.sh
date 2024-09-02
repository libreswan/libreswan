/testing/guestbin/swan-prep --hostkeys
echo 3 > /proc/sys/net/core/xfrm_acq_expires
# build install se module
../../guestbin/semodule.sh ipsecspd.te
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
# start the server
ipsec _getpeercon_server -d 4300
echo "initdone"
