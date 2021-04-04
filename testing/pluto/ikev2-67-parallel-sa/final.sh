hostname | grep nic > /dev/null || ipsec whack --trafficstatus
# policies and state should be multiple
ip xfrm state
ip xfrm policy
: ==== cut ====
ipsec auto --status
: ==== tuc ====
if [ -f /sbin/ausearch ]; then ausearch -r -m avc -ts recent ; fi
