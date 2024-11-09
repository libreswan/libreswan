grep -v -P "\t0$" /proc/net/xfrm_stat
# unique mark translates -1 to random, make sure there is no -1
ip xfrm policy | grep \\-1 
