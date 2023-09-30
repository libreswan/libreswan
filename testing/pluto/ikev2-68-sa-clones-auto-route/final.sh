ipsec whack --trafficstatus
# policies and state should be multiple
../../guestbin/ipsec-kernel-state.sh
ip xfrm policy
ipsec auto --status | grep westnet-eastnet
