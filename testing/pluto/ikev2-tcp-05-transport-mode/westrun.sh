# unfortunately does not yet indicate it is using TCP
ipsec up ikev2-west-east
../../guestbin/ping-once.sh --up 192.1.2.23
ipsec whack --trafficstatus
# should show tcp being used
ipsec _kernel state
ipsec _kernel policy 2>/dev/null | grep encap
ipsec _kernel state
ipsec _kernel policy
ipsec auto --down ikev2-west-east
echo "done"
