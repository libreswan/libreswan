/testing/guestbin/swan-prep
ipsec start
/testing/pluto/bin/wait-until-pluto-started
echo 1 > /proc/sys/net/core/xfrm_acq_expires
ipsec auto --add labeled
echo "initdone"
