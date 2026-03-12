hostname | grep nic > /dev/null || ipsec trafficstatus
grep -v -P "\t0$" /proc/net/xfrm_stat
