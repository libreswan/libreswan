hostname | grep nic > /dev/null || ipsec whack --trafficstatus
# policies and state should be multiple
ipsec _kernel state
ipsec _kernel policy
