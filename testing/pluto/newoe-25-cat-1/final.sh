hostname | grep nic > /dev/null || ipsec whack --trafficstatus
iptables -t nat -L -n
ipsec _kernel state
ipsec _kernel policy
