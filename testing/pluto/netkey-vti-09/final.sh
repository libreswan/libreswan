grep -v -P "\t0$" /proc/net/xfrm_stat
ip addr show
ip link show
ip route show
ip xfrm state
ip xfrm policy
: ==== cut ====
ipsec auto --status
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
