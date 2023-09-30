hostname | grep nic > /dev/null || ipsec whack --trafficstatus
iptables -t nat -L -n
../../guestbin/ipsec-kernel-state.sh
../../guestbin/ipsec-kernel-policy.sh
