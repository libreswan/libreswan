/testing/guestbin/swan-prep --hostkeys
echo 3 > /proc/sys/net/core/xfrm_acq_expires
# get pluto going
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add labeled
echo "initdone"
