ipsec whack --trafficstatus
# policies and state should be multiple
ip xfrm state
ip xfrm policy
ipsec auto --status | grep west-east
../bin/check-for-core.sh
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
: ==== end ====
