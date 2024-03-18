sysctl -w net.core.xfrm_iptfs_drop_time=1000
sysctl -w net.core.xfrm_iptfs_init_delay=1000
sysctl -w net.core.xfrm_iptfs_maxqsize=1048576
sysctl -w net.core.xfrm_iptfs_reorder_window=3
/testing/guestbin/swan-prep --46 --nokey
ipsec start
../../guestbin/wait-until-pluto-started
ipsec auto --add east
echo "initdone"
