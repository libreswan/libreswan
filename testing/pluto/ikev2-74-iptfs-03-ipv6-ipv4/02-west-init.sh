sysctl -w net.core.xfrm_iptfs_drptime=1000
sysctl -w net.core.xfrm_iptfs_idelay=1000
sysctl -w net.core.xfrm_iptfs_maxqsize=1048576
sysctl -w net.core.xfrm_iptfs_rewin=4
/testing/guestbin/swan-prep --46 --nokey
ip addr show eth0 | grep global | sort
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add west
echo "initdone"
