ipsec whack --trafficstatus
: ==== cut ====
ipsec auto --status
ip xfrm state
ip xfrm policy
: ==== tuc ====
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
