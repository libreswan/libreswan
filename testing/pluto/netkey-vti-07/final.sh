hostname | grep nic > /dev/null || ipsec whack --trafficstatus
grep -v -P "\t0$" /proc/net/xfrm_stat
