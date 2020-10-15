# 4 dropped packets should be visible on east because road leaked them
hostname | grep nic > /dev/null || ipsec whack --trafficstatus
grep -v -P "\t0$" /proc/net/xfrm_stat
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
